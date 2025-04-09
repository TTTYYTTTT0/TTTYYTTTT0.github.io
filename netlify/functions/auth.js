exports.handler = async (event) => {
  // 处理退出登录
  if (event.httpMethod === 'DELETE') {
    return {
      statusCode: 200,
      headers: {
        'Set-Cookie': 'token=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly; Secure; SameSite=Lax'
      },
      body: JSON.stringify({ success: true })
    };
  }

  // 检查登录状态
  if (event.httpMethod === 'GET') {
    const token = getTokenFromCookie(event);
    if (token) {
      return {
        statusCode: 200,
        body: JSON.stringify({ success: true, username: process.env.ADMIN_USER })
      };
    }
    return { statusCode: 401, body: JSON.stringify({ success: false }) };
  }

  // 处理登录
  if (event.httpMethod === 'POST') {
    const { username, password } = JSON.parse(event.body);
    if (username === process.env.ADMIN_USER && password === process.env.ADMIN_PASS) {
      const token = generateSecureToken(username);
      return {
        statusCode: 200,
        headers: {
          'Set-Cookie': `token=${token}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=86400`
        },
        body: JSON.stringify({ success: true, username })
      };
    }
    return { statusCode: 401, body: JSON.stringify({ success: false }) };
  }

  return { statusCode: 405, body: JSON.stringify({ error: 'Method not allowed' }) };
};

// 从 Cookie 提取 token
function getTokenFromCookie(event) {
  const cookies = event.headers.cookie || '';
  return cookies.split(';').find(c => c.trim().startsWith('token='))?.split('=')[1];
}

// 生成安全 token
function generateSecureToken(username) {
  return Buffer.from(`${username}:${Date.now()}:${Math.random()}`).toString('base64');
}
