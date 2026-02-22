require('dotenv').config();
const express = require('express');
const cors = require('cors');
const https = require('https');
const fs = require('fs');
const path = require('path');
const { encryptData, decryptData } = require('./crypto-utils');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;

// 加密密钥（用于加密存储的 API Token）
const ACCOUNTS_SECRET = process.env.ACCOUNTS_SECRET;
const ENCRYPTION_ENABLED = ACCOUNTS_SECRET && ACCOUNTS_SECRET.length === 64;

app.use(cors());
app.use(express.json());

// Session管理 - 存储在内存中,重启服务器后清空
const activeSessions = new Map(); // { token: { createdAt: timestamp } }
const SESSION_DURATION = 10 * 24 * 60 * 60 * 1000; // 10天
const MAX_SESSIONS = 100; // Session数量上限，防止内存泄漏

// 生成安全随机token
function generateToken() {
  return 'session_' + crypto.randomBytes(24).toString('hex');
}

// 清理过期session
function cleanExpiredSessions() {
  const now = Date.now();
  for (const [token, session] of activeSessions.entries()) {
    if (now - session.createdAt > SESSION_DURATION) {
      activeSessions.delete(token);
    }
  }
}

// 超出上限时淘汰最旧的session
function evictOldestSessions() {
  while (activeSessions.size >= MAX_SESSIONS) {
    let oldestToken = null, oldestTime = Infinity;
    for (const [token, session] of activeSessions.entries()) {
      if (session.createdAt < oldestTime) {
        oldestTime = session.createdAt;
        oldestToken = token;
      }
    }
    if (oldestToken) activeSessions.delete(oldestToken);
    else break;
  }
}

// 每15分钟清理一次过期session
setInterval(cleanExpiredSessions, 15 * 60 * 1000);

// 密码验证中间件
function requireAuth(req, res, next) {
  const password = req.headers['x-admin-password'];
  const sessionToken = req.headers['x-session-token'];
  const savedPassword = loadAdminPassword();
  
  if (!savedPassword) {
    // 如果没有设置密码，允许访问（首次设置）
    next();
  } else if (sessionToken && activeSessions.has(sessionToken)) {
    // 检查session是否有效
    const session = activeSessions.get(sessionToken);
    if (Date.now() - session.createdAt < SESSION_DURATION) {
      next();
    } else {
      activeSessions.delete(sessionToken);
      res.status(401).json({ error: 'Session已过期，请重新登录' });
    }
  } else if (password === savedPassword) {
    next();
  } else {
    res.status(401).json({ error: '密码错误或Session无效' });
  }
}

app.use(express.static('public'));

// 数据文件路径（统一放在 data 目录，方便 Docker 持久化挂载）
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
if (!fs.existsSync(DATA_DIR)) { fs.mkdirSync(DATA_DIR, { recursive: true }); }
const ACCOUNTS_FILE = path.join(DATA_DIR, 'accounts.json');
const PASSWORD_FILE = path.join(DATA_DIR, 'password.json');
const BARK_SETTINGS_FILE = path.join(DATA_DIR, 'bark-settings.json');

// 文件 I/O 缓存（减少磁盘读取）
let _cachedServerAccounts = undefined;
let _cachedAdminPassword = undefined;
let _cachedBarkSettings = undefined;

// 读取服务器存储的账号
function loadServerAccounts() {
  if (_cachedServerAccounts !== undefined) return _cachedServerAccounts;
  try {
    if (fs.existsSync(ACCOUNTS_FILE)) {
      const data = fs.readFileSync(ACCOUNTS_FILE, 'utf8');
      let accounts = JSON.parse(data);

      // 如果启用了加密,解密 Token
      if (ENCRYPTION_ENABLED) {
        accounts = accounts.map(account => {
          // 如果账号有加密的 Token,解密它
          if (account.encryptedToken) {
            try {
              const token = decryptData(account.encryptedToken, ACCOUNTS_SECRET);
              return { ...account, token, encryptedToken: undefined };
            } catch (e) {
              console.error(`❌ 解密账号 [${account.name}] 的 Token 失败:`, e.message);
              return account;
            }
          }
          return account;
        });
      }

      _cachedServerAccounts = accounts;
      return accounts;
    }
  } catch (e) {
    console.error('❌ 读取账号文件失败:', e.message);
  }
  _cachedServerAccounts = [];
  return [];
}

// 保存账号到服务器
function saveServerAccounts(accounts) {
  _cachedServerAccounts = undefined; // 失效缓存
  try {
    let accountsToSave = accounts;
    
    // 如果启用了加密,加密 Token
    if (ENCRYPTION_ENABLED) {
      accountsToSave = accounts.map(account => {
        if (account.token) {
          try {
            const encryptedToken = encryptData(account.token, ACCOUNTS_SECRET);
            // 保存时移除明文 token,只保存加密后的
            const { token, ...rest } = account;
            return { ...rest, encryptedToken };
          } catch (e) {
            console.error(`❌ 加密账号 [${account.name}] 的 Token 失败:`, e.message);
            return account;
          }
        }
        return account;
      });
      console.log('🔐 账号 Token 已加密存储');
    }
    
    fs.writeFileSync(ACCOUNTS_FILE, JSON.stringify(accountsToSave, null, 2), 'utf8');
    return true;
  } catch (e) {
    console.error('❌ 保存账号文件失败:', e.message);
    return false;
  }
}

// 读取管理员密码
function loadAdminPassword() {
  if (_cachedAdminPassword !== undefined) return _cachedAdminPassword;
  try {
    if (fs.existsSync(PASSWORD_FILE)) {
      const data = fs.readFileSync(PASSWORD_FILE, 'utf8');
      _cachedAdminPassword = JSON.parse(data).password;
      return _cachedAdminPassword;
    }
  } catch (e) {
    console.error('❌ 读取密码文件失败:', e.message);
  }
  _cachedAdminPassword = null;
  return null;
}

// 保存管理员密码
function saveAdminPassword(password) {
  _cachedAdminPassword = undefined; // 失效缓存
  try {
    fs.writeFileSync(PASSWORD_FILE, JSON.stringify({ password }, null, 2), 'utf8');
    return true;
  } catch (e) {
    console.error('❌ 保存密码文件失败:', e.message);
    return false;
  }
}

// Zeabur GraphQL 查询（内部单次请求）
function _queryZeaburOnce(token, query, variables = null) {
  return new Promise((resolve, reject) => {
    const payload = variables ? { query, variables } : { query };
    const data = JSON.stringify(payload);
    const options = {
      hostname: 'api.zeabur.com',
      path: '/graphql',
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(data)
      },
      timeout: 10000
    };

    const req = https.request(options, (res) => {
      let body = '';
      res.on('data', (chunk) => body += chunk);
      res.on('end', () => {
        try {
          resolve(JSON.parse(body));
        } catch (e) {
          reject(new Error('Invalid JSON response'));
        }
      });
    });

    req.on('error', reject);
    req.on('timeout', () => {
      req.destroy();
      reject(new Error('Request timeout'));
    });
    req.write(data);
    req.end();
  });
}

// 带重试的 GraphQL 查询（1次重试，1秒延迟）
async function queryZeabur(token, query, variables = null) {
  try {
    return await _queryZeaburOnce(token, query, variables);
  } catch (err) {
    await new Promise(r => setTimeout(r, 1000));
    return _queryZeaburOnce(token, query, variables);
  }
}

// 获取用户信息和项目
async function fetchAccountData(token) {
  // 查询用户信息
  const userQuery = `
    query {
      me {
        _id
        username
        email
        credit
      }
    }
  `;
  
  // 查询项目信息
  const projectsQuery = `
    query {
      projects {
        edges {
          node {
            _id
            name
            region {
              name
            }
            environments {
              _id
            }
            services {
              _id
              name
              status
              template
              resourceLimit {
                cpu
                memory
              }
              domains {
                _id
                domain
                isGenerated
              }
            }
          }
        }
      }
    }
  `;
  
  // 查询 AI Hub 余额
  const aihubQuery = `
    query GetAIHubTenant {
      aihubTenant {
        balance
        keys {
          keyID
          alias
          cost
        }
      }
    }
  `;
  
  const [userData, projectsData, aihubData] = await Promise.all([
    queryZeabur(token, userQuery),
    queryZeabur(token, projectsQuery),
    queryZeabur(token, aihubQuery).catch(() => ({ data: { aihubTenant: null } }))
  ]);
  
  return {
    user: userData.data?.me || {},
    projects: (projectsData.data?.projects?.edges || []).map(edge => edge.node),
    aihub: aihubData.data?.aihubTenant || null
  };
}

// 获取项目用量数据（复用 queryZeabur）
async function fetchUsageData(token, userID, projects = []) {
  const now = new Date();
  const year = now.getFullYear();
  const month = now.getMonth() + 1;
  const fromDate = `${year}-${String(month).padStart(2, '0')}-01`;
  // 使用明天的日期确保包含今天的所有数据
  const tomorrow = new Date(now);
  tomorrow.setDate(tomorrow.getDate() + 1);
  const toDate = `${tomorrow.getFullYear()}-${String(tomorrow.getMonth() + 1).padStart(2, '0')}-${String(tomorrow.getDate()).padStart(2, '0')}`;

  const usageGql = `query GetHeaderMonthlyUsage($from: String!, $to: String!, $groupByEntity: GroupByEntity, $groupByTime: GroupByTime, $groupByType: GroupByType, $userID: ObjectID!) {
    usages(from: $from, to: $to, groupByEntity: $groupByEntity, groupByTime: $groupByTime, groupByType: $groupByType, userID: $userID) {
      categories
      data { id name groupByEntity usageOfEntity __typename }
      __typename
    }
  }`;

  const result = await queryZeabur(token, usageGql, {
    from: fromDate, to: toDate,
    groupByEntity: 'PROJECT', groupByTime: 'DAY', groupByType: 'ALL',
    userID
  });

  const usages = result.data?.usages?.data || [];
  const projectCosts = {};
  let totalUsage = 0;

  usages.forEach(project => {
    const projectTotal = project.usageOfEntity.reduce((a, b) => a + b, 0);
    // 单个项目显示：向上取整到 $0.01（与 Zeabur 官方一致）
    const displayCost = projectTotal > 0 ? Math.ceil(projectTotal * 100) / 100 : 0;
    projectCosts[project.id] = displayCost;
    // 总用量计算：使用原始费用（不取整，保证总余额准确）
    totalUsage += projectTotal;
  });

  return {
    projectCosts,
    totalUsage,
    freeQuotaRemaining: 5 - totalUsage, // 免费额度 $5
    freeQuotaLimit: 5
  };
}

// 合并端点 - 一次请求返回账号信息和项目数据（减少 50% GraphQL 调用）
app.post('/api/dashboard-data', requireAuth, express.json(), async (req, res) => {
  const { accounts } = req.body;

  if (!accounts || !Array.isArray(accounts)) {
    return res.status(400).json({ error: '无效的账号列表' });
  }

  const results = await Promise.all(accounts.map(async (account) => {
    try {
      const { user, projects, aihub } = await fetchAccountData(account.token);

      let usageData = { totalUsage: 0, freeQuotaRemaining: 5, freeQuotaLimit: 5, projectCosts: {} };
      if (user._id) {
        try {
          usageData = await fetchUsageData(account.token, user._id, projects);
        } catch (e) {
          console.log(`⚠️ [${account.name}] 获取用量失败:`, e.message);
        }
      }

      const creditInCents = Math.round(usageData.freeQuotaRemaining * 100);

      const projectsWithCost = projects.map(project => {
        const cost = (usageData.projectCosts || {})[project._id] || 0;
        return {
          _id: project._id,
          name: project.name,
          region: project.region?.name || 'Unknown',
          environments: project.environments || [],
          services: project.services || [],
          cost,
          hasCostData: cost > 0
        };
      });

      return {
        name: account.name,
        success: true,
        data: {
          ...user,
          credit: creditInCents,
          totalUsage: usageData.totalUsage,
          freeQuotaLimit: usageData.freeQuotaLimit
        },
        aihub,
        projects: projectsWithCost
      };
    } catch (error) {
      console.error(`❌ [${account.name}] 错误:`, error.message);
      return { name: account.name, success: false, error: error.message };
    }
  }));

  res.json(results);
});

// 验证账号
app.post('/api/validate-account', requireAuth, express.json(), async (req, res) => {
  const { accountName, apiToken } = req.body;
  
  if (!accountName || !apiToken) {
    return res.status(400).json({ error: '账号名称和 API Token 不能为空' });
  }
  
  try {
    const { user } = await fetchAccountData(apiToken);
    
    if (user._id) {
      res.json({
        success: true,
        message: '账号验证成功！',
        userData: user,
        accountName
      });
    } else {
      res.status(400).json({ error: 'API Token 无效或没有权限' });
    }
  } catch (error) {
    res.status(400).json({ error: 'API Token 验证失败: ' + error.message });
  }
});

// 从环境变量读取预配置的账号
function getEnvAccounts() {
  const accountsEnv = process.env.ACCOUNTS;
  if (!accountsEnv) return [];
  
  try {
    // 格式: "账号1名称:token1,账号2名称:token2"
    return accountsEnv.split(',').map(item => {
      const [name, token] = item.split(':');
      return { name: name.trim(), token: token.trim() };
    }).filter(acc => acc.name && acc.token);
  } catch (e) {
    console.error('❌ 解析环境变量 ACCOUNTS 失败:', e.message);
    return [];
  }
}

// 检查加密密钥是否已设置
app.get('/api/check-encryption', (req, res) => {
  const suggestedSecret = crypto.randomBytes(32).toString('hex');
  res.json({
    isConfigured: ENCRYPTION_ENABLED,
    suggestedSecret
  });
});

app.get('/api/check-password', (req, res) => {
  const savedPassword = loadAdminPassword();
  res.json({ hasPassword: !!savedPassword });
});

// 设置管理员密码（首次）
app.post('/api/set-password', (req, res) => {
  const { password } = req.body;
  const savedPassword = loadAdminPassword();
  
  if (savedPassword) {
    return res.status(400).json({ error: '密码已设置，无法重复设置' });
  }
  
  if (!password || password.length < 6) {
    return res.status(400).json({ error: '密码长度至少6位' });
  }
  
  if (saveAdminPassword(password)) {
    console.log('✅ 管理员密码已设置');
    res.json({ success: true });
  } else {
    res.status(500).json({ error: '保存密码失败' });
  }
});

// 登录暴力破解防护（基于 IP 的简单限速）
const loginAttempts = new Map(); // { ip: { count, firstAttempt } }
const LOGIN_WINDOW = 15 * 60 * 1000; // 15分钟窗口
const MAX_LOGIN_ATTEMPTS = 10;

// 定期清理过期记录
setInterval(() => {
  const now = Date.now();
  for (const [ip, data] of loginAttempts.entries()) {
    if (now - data.firstAttempt > LOGIN_WINDOW) loginAttempts.delete(ip);
  }
}, 5 * 60 * 1000);

// 验证密码
app.post('/api/verify-password', (req, res) => {
  const clientIp = req.ip || req.connection.remoteAddress;
  const now = Date.now();
  const attempts = loginAttempts.get(clientIp);

  if (attempts) {
    if (now - attempts.firstAttempt > LOGIN_WINDOW) {
      loginAttempts.delete(clientIp);
    } else if (attempts.count >= MAX_LOGIN_ATTEMPTS) {
      const retryAfter = Math.ceil((LOGIN_WINDOW - (now - attempts.firstAttempt)) / 1000);
      return res.status(429).json({ success: false, error: `登录尝试过多，请 ${retryAfter} 秒后重试` });
    }
  }

  const { password } = req.body;
  const savedPassword = loadAdminPassword();
  
  if (!savedPassword) {
    return res.status(400).json({ success: false, error: '请先设置密码' });
  }
  
  if (password === savedPassword) {
    // 登录成功，清除限速记录
    loginAttempts.delete(clientIp);
    // 生成新的session token（超限时淘汰最旧的）
    evictOldestSessions();
    const sessionToken = generateToken();
    activeSessions.set(sessionToken, { createdAt: Date.now() });
    console.log(`✅ 用户登录成功，生成Session: ${sessionToken.substring(0, 20)}...`);
    res.json({ success: true, sessionToken });
  } else {
    // 登录失败，记录尝试次数
    const record = loginAttempts.get(clientIp);
    if (record) {
      record.count++;
    } else {
      loginAttempts.set(clientIp, { count: 1, firstAttempt: Date.now() });
    }
    res.status(401).json({ success: false, error: '密码错误' });
  }
});

// 获取所有账号（服务器存储 + 环境变量，分开返回）
app.get('/api/server-accounts', requireAuth, async (req, res) => {
  const serverAccounts = loadServerAccounts();
  const envAccounts = getEnvAccounts();

  console.log(`📋 返回账号 (环境变量: ${envAccounts.length}, 服务器: ${serverAccounts.length})`);
  res.json({
    envAccounts: envAccounts,
    serverAccounts: serverAccounts
  });
});

// 保存账号到服务器
app.post('/api/server-accounts', requireAuth, async (req, res) => {
  const { accounts } = req.body;
  
  if (!accounts || !Array.isArray(accounts)) {
    return res.status(400).json({ error: '无效的账号列表' });
  }
  
  if (saveServerAccounts(accounts)) {
    console.log(`✅ 保存 ${accounts.length} 个账号到服务器`);
    res.json({ success: true, message: '账号已保存到服务器' });
  } else {
    res.status(500).json({ error: '保存失败' });
  }
});

// 暂停服务
app.post('/api/service/pause', requireAuth, async (req, res) => {
  const { token, serviceId, environmentId } = req.body;
  
  if (!token || !serviceId || !environmentId) {
    return res.status(400).json({ error: '缺少必要参数' });
  }
  
  try {
    const mutation = `mutation($serviceID: ObjectID!, $environmentID: ObjectID!) { suspendService(serviceID: $serviceID, environmentID: $environmentID) }`;
    const result = await queryZeabur(token, mutation, { serviceID: serviceId, environmentID: environmentId });
    
    if (result.data?.suspendService) {
      res.json({ success: true, message: '服务已暂停' });
    } else {
      res.status(400).json({ error: '暂停失败', details: result });
    }
  } catch (error) {
    res.status(500).json({ error: '暂停服务失败: ' + error.message });
  }
});

// 重启服务
app.post('/api/service/restart', requireAuth, async (req, res) => {
  const { token, serviceId, environmentId } = req.body;
  
  if (!token || !serviceId || !environmentId) {
    return res.status(400).json({ error: '缺少必要参数' });
  }
  
  try {
    const mutation = `mutation($serviceID: ObjectID!, $environmentID: ObjectID!) { restartService(serviceID: $serviceID, environmentID: $environmentID) }`;
    const result = await queryZeabur(token, mutation, { serviceID: serviceId, environmentID: environmentId });
    
    if (result.data?.restartService) {
      res.json({ success: true, message: '服务已重启' });
    } else {
      res.status(400).json({ error: '重启失败', details: result });
    }
  } catch (error) {
    res.status(500).json({ error: '重启服务失败: ' + error.message });
  }
});

// 获取服务日志
app.post('/api/service/logs', requireAuth, express.json(), async (req, res) => {
  const { token, serviceId, environmentId, projectId, limit = 200 } = req.body;
  
  if (!token || !serviceId || !environmentId || !projectId) {
    return res.status(400).json({ error: '缺少必要参数' });
  }
  
  try {
    const query = `
      query($projectID: ObjectID!, $serviceID: ObjectID!, $environmentID: ObjectID!) {
        runtimeLogs(
          projectID: $projectID
          serviceID: $serviceID
          environmentID: $environmentID
        ) {
          message
          timestamp
        }
      }
    `;

    const result = await queryZeabur(token, query, { projectID: projectId, serviceID: serviceId, environmentID: environmentId });
    
    if (result.data?.runtimeLogs) {
      // 按时间戳排序，最新的在最后
      const sortedLogs = result.data.runtimeLogs.sort((a, b) => {
        return new Date(a.timestamp) - new Date(b.timestamp);
      });
      
      // 获取最后 N 条日志
      const logs = sortedLogs.slice(-limit);
      
      res.json({ 
        success: true, 
        logs,
        count: logs.length,
        totalCount: result.data.runtimeLogs.length
      });
    } else {
      res.status(400).json({ error: '获取日志失败', details: result });
    }
  } catch (error) {
    res.status(500).json({ error: '获取日志失败: ' + error.message });
  }
});

// 重命名项目
app.post('/api/project/rename', requireAuth, async (req, res) => {
  const { accountId, projectId, newName } = req.body;

  if (!accountId || !projectId || !newName) {
    return res.status(400).json({ error: '缺少必要参数' });
  }
  
  try {
    // 从服务器存储和环境变量中获取账号token
    const serverAccounts = loadServerAccounts();
    const envAccounts = getEnvAccounts();
    const allAccounts = [...envAccounts, ...serverAccounts];
    const account = allAccounts.find(acc => (acc.id || acc.name) === accountId);
    
    if (!account || !account.token) {
      return res.status(404).json({ error: '未找到账号或token' });
    }
    
    const mutation = `mutation($id: ObjectID!, $name: String!) { renameProject(_id: $id, name: $name) }`;
    const result = await queryZeabur(account.token, mutation, { id: projectId, name: newName });

    if (result.data?.renameProject) {
      res.json({ success: true, message: '项目已重命名' });
    } else {
      res.status(400).json({ error: '重命名失败', details: result });
    }
  } catch (error) {
    res.status(500).json({ error: '重命名项目失败: ' + error.message });
  }
});

// 获取当前版本
app.get('/api/version', (req, res) => {
  const packageJson = require('./package.json');
  res.json({ version: packageJson.version });
});

// 获取GitHub最新版本
app.get('/api/latest-version', async (req, res) => {
  let responded = false;
  function sendOnce(status, data) {
    if (responded) return;
    responded = true;
    res.status(status).json(data);
  }
  try {
    const options = {
      hostname: 'raw.githubusercontent.com',
      path: '/jiujiu532/zeabur-monitor/main/package.json',
      method: 'GET',
      timeout: 5000
    };

    const request = https.request(options, (response) => {
      let data = '';
      response.on('data', (chunk) => data += chunk);
      response.on('end', () => {
        try {
          const packageJson = JSON.parse(data);
          sendOnce(200, { version: packageJson.version });
        } catch (e) {
          sendOnce(500, { error: '解析版本信息失败' });
        }
      });
    });

    request.on('error', (error) => {
      sendOnce(500, { error: '获取最新版本失败: ' + error.message });
    });

    request.on('timeout', () => {
      request.destroy();
      sendOnce(500, { error: '请求超时' });
    });

    request.end();
  } catch (error) {
    sendOnce(500, { error: '获取最新版本失败: ' + error.message });
  }
});

// ============ Bark 通知系统 ============

function loadBarkSettings() {
  if (_cachedBarkSettings !== undefined) return _cachedBarkSettings;
  try {
    if (fs.existsSync(BARK_SETTINGS_FILE)) {
      _cachedBarkSettings = JSON.parse(fs.readFileSync(BARK_SETTINGS_FILE, 'utf8'));
      return _cachedBarkSettings;
    }
  } catch (e) {
    console.error('❌ 读取 Bark 配置失败:', e.message);
  }
  _cachedBarkSettings = { url: '', deviceKey: '', enabled: false, interval: 5, notifyServiceDown: true, notifyServiceRecovery: true, notifyBalanceLow: true, balanceThreshold: 100 };
  return _cachedBarkSettings;
}

function saveBarkSettings(settings) {
  _cachedBarkSettings = undefined; // 失效缓存
  try {
    fs.writeFileSync(BARK_SETTINGS_FILE, JSON.stringify(settings, null, 2), 'utf8');
    return true;
  } catch (e) {
    console.error('❌ 保存 Bark 配置失败:', e.message);
    return false;
  }
}

async function sendBarkNotification(title, body, group = 'zeabur-monitor') {
  const settings = loadBarkSettings();
  if (!settings.enabled || !settings.url || !settings.deviceKey) return false;

  const url = settings.url.replace(/\/+$/, '');
  const pushUrl = `${url}/push`;

  return new Promise((resolve) => {
    const payload = JSON.stringify({
      device_key: settings.deviceKey,
      title, body, group,
      icon: 'https://zeabur.com/favicon.ico',
      level: 'timeSensitive'
    });

    const urlObj = new URL(pushUrl);
    const options = {
      hostname: urlObj.hostname,
      port: urlObj.port || (urlObj.protocol === 'https:' ? 443 : 80),
      path: urlObj.pathname,
      method: 'POST',
      headers: { 'Content-Type': 'application/json; charset=utf-8', 'Content-Length': Buffer.byteLength(payload) },
      timeout: 10000
    };

    const transport = urlObj.protocol === 'https:' ? https : require('http');
    const req = transport.request(options, (res) => {
      let data = '';
      res.on('data', (chunk) => data += chunk);
      res.on('end', () => {
        try {
          const result = JSON.parse(data);
          resolve(result.code === 200);
        } catch { resolve(false); }
      });
    });
    req.on('error', () => resolve(false));
    req.on('timeout', () => { req.destroy(); resolve(false); });
    req.write(payload);
    req.end();
  });
}

// Bark 监控状态
let previousServiceStates = new Map();
let barkMonitorInterval = null;
let barkMonitorRunning = false; // 防止重叠执行

async function runBarkMonitor() {
  if (barkMonitorRunning) return; // 上一轮未完成则跳过
  barkMonitorRunning = true;

  const settings = loadBarkSettings();
  if (!settings.enabled) { barkMonitorRunning = false; return; }

  const currentKeys = new Set(); // 追踪本轮活跃的 key

  try {
    const serverAccounts = loadServerAccounts();
    const envAccounts = getEnvAccounts();
    const allAccounts = [...envAccounts, ...serverAccounts];
    if (allAccounts.length === 0) { barkMonitorRunning = false; return; }

    const results = await Promise.allSettled(allAccounts.map(async (account) => {
      try {
        const { user, projects } = await fetchAccountData(account.token);

        // 检查余额
        if (settings.notifyBalanceLow && user._id) {
          try {
            const usageData = await fetchUsageData(account.token, user._id, projects);
            const remainingCents = Math.round(usageData.freeQuotaRemaining * 100);
            const balanceKey = `balance_${account.name}`;
            currentKeys.add(balanceKey);
            const prevBalance = previousServiceStates.get(balanceKey);
            if (remainingCents <= settings.balanceThreshold && prevBalance !== 'low') {
              await sendBarkNotification('Zeabur Balance Low', `Account "${account.name}" balance is $${(remainingCents / 100).toFixed(2)}, below threshold $${(settings.balanceThreshold / 100).toFixed(2)}`);
              previousServiceStates.set(balanceKey, 'low');
            } else if (remainingCents > settings.balanceThreshold) {
              previousServiceStates.set(balanceKey, 'ok');
            }
          } catch (e) { /* ignore usage fetch errors */ }
        }

        // 检查服务状态
        for (const project of projects) {
          for (const service of (project.services || [])) {
            const stateKey = `service_${account.name}_${project._id}_${service._id}`;
            currentKeys.add(stateKey);
            const prevStatus = previousServiceStates.get(stateKey);

            if (prevStatus && prevStatus !== service.status) {
              if (settings.notifyServiceDown && prevStatus === 'RUNNING' && service.status !== 'RUNNING') {
                await sendBarkNotification('Service Down', `"${service.name}" in project "${project.name}" (${account.name}) is now ${service.status}`);
              }
              if (settings.notifyServiceRecovery && prevStatus !== 'RUNNING' && service.status === 'RUNNING') {
                await sendBarkNotification('Service Recovered', `"${service.name}" in project "${project.name}" (${account.name}) is now RUNNING`);
              }
            }
            previousServiceStates.set(stateKey, service.status);
          }
        }
      } catch (e) {
        console.log(`⚠️ Bark 监控 [${account.name}] 失败:`, e.message);
      }
    }));

    // 清理已删除账号/服务的残留 key，防止内存泄漏
    for (const key of previousServiceStates.keys()) {
      if (!currentKeys.has(key)) previousServiceStates.delete(key);
    }
  } catch (e) {
    console.error('❌ Bark 监控异常:', e.message);
  } finally {
    barkMonitorRunning = false;
  }
}

function startBarkMonitor() {
  if (barkMonitorInterval) clearInterval(barkMonitorInterval);
  const settings = loadBarkSettings();
  if (settings.enabled && settings.url && settings.deviceKey) {
    const intervalMs = (settings.interval || 5) * 60 * 1000;
    barkMonitorInterval = setInterval(runBarkMonitor, intervalMs);
    // 首次延迟30秒执行，让服务完全启动
    setTimeout(runBarkMonitor, 30000);
    console.log(`🔔 Bark 通知已启用 (每${settings.interval}分钟检查)`);
  }
}

// ============ 域名管理 API ============

app.post('/api/service/domain/remove', requireAuth, async (req, res) => {
  const { token, domainId } = req.body;
  if (!token || !domainId) {
    return res.status(400).json({ error: '缺少必要参数' });
  }
  try {
    const mutation = `mutation($id: ObjectID!) { removeDomain(_id: $id) }`;
    const result = await queryZeabur(token, mutation, { id: domainId });
    if (result.data) {
      res.json({ success: true });
    } else {
      res.status(400).json({ error: '删除域名失败', details: result.errors?.[0]?.message || JSON.stringify(result) });
    }
  } catch (error) {
    res.status(500).json({ error: '删除域名失败: ' + error.message });
  }
});

// ============ 环境变量管理 API ============

app.post('/api/service/env/list', requireAuth, async (req, res) => {
  const { token, serviceId, environmentId } = req.body;
  if (!token || !serviceId || !environmentId) {
    return res.status(400).json({ error: '缺少必要参数' });
  }
  try {
    const query = `query($serviceID: ObjectID!, $environmentID: ObjectID!) {
      environmentVariables(serviceID: $serviceID, environmentID: $environmentID) { key value }
    }`;
    const result = await queryZeabur(token, query, { serviceID: serviceId, environmentID: environmentId });
    if (result.data?.environmentVariables) {
      res.json({ success: true, variables: result.data.environmentVariables });
    } else {
      res.status(400).json({ error: '获取环境变量失败', details: result.errors?.[0]?.message || JSON.stringify(result) });
    }
  } catch (error) {
    res.status(500).json({ error: '获取环境变量失败: ' + error.message });
  }
});

app.post('/api/service/env/update', requireAuth, async (req, res) => {
  const { token, serviceId, environmentId, key, value } = req.body;
  if (!token || !serviceId || !environmentId || !key) {
    return res.status(400).json({ error: '缺少必要参数' });
  }
  try {
    const query = `mutation($serviceID: ObjectID!, $environmentID: ObjectID!, $key: String!, $value: String!) {
      updateSingleEnvironmentVariable(serviceID: $serviceID, environmentID: $environmentID, key: $key, value: $value) { key value }
    }`;
    const result = await queryZeabur(token, query, { serviceID: serviceId, environmentID: environmentId, key, value: value || '' });
    if (result.data?.updateSingleEnvironmentVariable) {
      res.json({ success: true });
    } else {
      res.status(400).json({ error: '更新环境变量失败', details: result.errors?.[0]?.message || JSON.stringify(result) });
    }
  } catch (error) {
    res.status(500).json({ error: '更新环境变量失败: ' + error.message });
  }
});

app.post('/api/service/env/delete', requireAuth, async (req, res) => {
  const { token, serviceId, environmentId, key } = req.body;
  if (!token || !serviceId || !environmentId || !key) {
    return res.status(400).json({ error: '缺少必要参数' });
  }
  try {
    const query = `mutation($serviceID: ObjectID!, $environmentID: ObjectID!, $key: String!) {
      deleteSingleEnvironmentVariable(serviceID: $serviceID, environmentID: $environmentID, key: $key)
    }`;
    const result = await queryZeabur(token, query, { serviceID: serviceId, environmentID: environmentId, key });
    if (result.data) {
      res.json({ success: true });
    } else {
      res.status(400).json({ error: '删除环境变量失败', details: result.errors?.[0]?.message || JSON.stringify(result) });
    }
  } catch (error) {
    res.status(500).json({ error: '删除环境变量失败: ' + error.message });
  }
});

// ============ 部署和构建日志 API ============

app.post('/api/service/deployments', requireAuth, async (req, res) => {
  const { token, serviceId, environmentId } = req.body;
  if (!token || !serviceId || !environmentId) {
    return res.status(400).json({ error: '缺少必要参数' });
  }
  try {
    const query = `query($serviceID: ObjectID!, $environmentID: ObjectID!) {
      deployments(serviceID: $serviceID, environmentID: $environmentID, perPage: 10) {
        edges { node { _id status createdAt } }
      }
    }`;
    const result = await queryZeabur(token, query, { serviceID: serviceId, environmentID: environmentId });
    if (result.data?.deployments?.edges) {
      const deployments = result.data.deployments.edges.map(e => e.node);
      res.json({ success: true, deployments });
    } else {
      res.status(400).json({ error: '获取部署列表失败', details: result.errors?.[0]?.message || JSON.stringify(result) });
    }
  } catch (error) {
    res.status(500).json({ error: '获取部署列表失败: ' + error.message });
  }
});

app.post('/api/service/build-logs', requireAuth, async (req, res) => {
  const { token, deploymentId } = req.body;
  if (!token || !deploymentId) {
    return res.status(400).json({ error: '缺少必要参数' });
  }
  try {
    const query = `query($deploymentID: ObjectID!) {
      buildLogs(deploymentID: $deploymentID) { message timestamp }
    }`;
    const result = await queryZeabur(token, query, { deploymentID: deploymentId });
    if (result.data?.buildLogs) {
      res.json({ success: true, logs: result.data.buildLogs });
    } else {
      res.status(400).json({ error: '获取构建日志失败', details: result.errors?.[0]?.message || JSON.stringify(result) });
    }
  } catch (error) {
    res.status(500).json({ error: '获取构建日志失败: ' + error.message });
  }
});

// ============ 用量明细 API ============

app.post('/api/usage/detail', requireAuth, async (req, res) => {
  const { token, userId } = req.body;
  if (!token || !userId) {
    return res.status(400).json({ error: '缺少必要参数' });
  }

  const now = new Date();
  const year = now.getFullYear();
  const month = now.getMonth() + 1;
  const fromDate = `${year}-${String(month).padStart(2, '0')}-01`;
  const tomorrow = new Date(now);
  tomorrow.setDate(tomorrow.getDate() + 1);
  const toDate = `${tomorrow.getFullYear()}-${String(tomorrow.getMonth() + 1).padStart(2, '0')}-${String(tomorrow.getDate()).padStart(2, '0')}`;

  try {
    const queryStr = `query($from: String!, $to: String!, $userID: ObjectID!, $groupByEntity: GroupByEntity, $groupByTime: GroupByTime, $groupByType: GroupByType) {
      usages(from: $from, to: $to, userID: $userID, groupByEntity: $groupByEntity, groupByTime: $groupByTime, groupByType: $groupByType) {
        categories
        data { id name groupByEntity usageOfEntity }
      }
    }`;

    const types = ['CPU', 'MEMORY', 'NETWORK'];
    const results = await Promise.all(types.map(type =>
      queryZeabur(token, queryStr, {
        from: fromDate, to: toDate, userID: userId,
        groupByEntity: 'SERVICE', groupByTime: 'DAY', groupByType: type
      })
    ));

    const usageByType = {};
    types.forEach((type, i) => {
      const data = results[i]?.data?.usages?.data || [];
      usageByType[type] = data.map(item => ({
        id: item.id,
        name: item.name,
        total: item.usageOfEntity.reduce((a, b) => a + b, 0)
      }));
    });

    // 也获取总费用按服务分
    const totalResult = await queryZeabur(token, queryStr, {
      from: fromDate, to: toDate, userID: userId,
      groupByEntity: 'SERVICE', groupByTime: 'DAY', groupByType: 'ALL'
    });

    const serviceUsage = (totalResult?.data?.usages?.data || []).map(item => ({
      id: item.id,
      name: item.name,
      total: item.usageOfEntity.reduce((a, b) => a + b, 0),
      daily: item.usageOfEntity
    }));

    res.json({
      success: true,
      categories: totalResult?.data?.usages?.categories || [],
      serviceUsage,
      usageByType,
      period: `${fromDate} ~ ${toDate}`
    });
  } catch (error) {
    res.status(500).json({ error: '获取用量明细失败: ' + error.message });
  }
});

// ============ Bark 设置 API ============

app.get('/api/settings/bark', requireAuth, (req, res) => {
  const settings = loadBarkSettings();
  res.json(settings);
});

app.post('/api/settings/bark', requireAuth, (req, res) => {
  const settings = req.body;
  if (saveBarkSettings(settings)) {
    startBarkMonitor();
    res.json({ success: true });
  } else {
    res.status(500).json({ error: '保存失败' });
  }
});

app.post('/api/bark/test', requireAuth, async (req, res) => {
  const { url, deviceKey } = req.body;
  if (!url || !deviceKey) {
    return res.status(400).json({ error: '请填写 Bark URL 和 Device Key' });
  }
  // 临时覆盖设置发送测试
  const origSettings = loadBarkSettings();
  const testSettings = { ...origSettings, url, deviceKey, enabled: true };
  saveBarkSettings(testSettings);
  const success = await sendBarkNotification('Zeabur Monitor', 'Bark notification test successful!', 'test');
  // 恢复原设置（如果测试用了不同配置）
  if (!origSettings.url) {
    saveBarkSettings(testSettings); // 保留新设置
  }
  if (success) {
    res.json({ success: true, message: '测试通知已发送' });
  } else {
    res.status(400).json({ error: '发送失败，请检查 URL 和 Device Key' });
  }
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`✨ Zeabur Monitor 运行在 http://0.0.0.0:${PORT}`);
  
  // 显示加密状态
  if (ENCRYPTION_ENABLED) {
    console.log(`🔐 Token 加密存储: 已启用 (AES-256-GCM)`);
  } else {
    console.log(`⚠️  Token 加密存储: 未启用 (建议设置 ACCOUNTS_SECRET 环境变量)`);
  }
  
  const envAccounts = getEnvAccounts();
  const serverAccounts = loadServerAccounts();
  const totalAccounts = envAccounts.length + serverAccounts.length;
  
  if (totalAccounts > 0) {
    console.log(`📋 已加载 ${totalAccounts} 个账号`);
    if (envAccounts.length > 0) {
      console.log(`   环境变量: ${envAccounts.length} 个`);
      envAccounts.forEach(acc => console.log(`     - ${acc.name}`));
    }
    if (serverAccounts.length > 0) {
      console.log(`   服务器存储: ${serverAccounts.length} 个`);
      serverAccounts.forEach(acc => console.log(`     - ${acc.name}`));
    }
  } else {
    console.log(`📊 准备就绪，等待添加账号...`);
  }

  // 启动 Bark 监控
  startBarkMonitor();
});
