exports.handler = async (event) => {
    // 统一设置安全响应头
    const securityHeaders = {
        "Access-Control-Allow-Origin": "https://tttyytttt.netlify.app",
        "Access-Control-Allow-Credentials": "true",
        "Content-Security-Policy": "default-src 'self'"
    };

    // 处理退出登录
    if (event.httpMethod === 'DELETE') {
        return {
            statusCode: 200,
            headers: {
                ...securityHeaders,
                'Set-Cookie': 'token=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly; Secure; SameSite=Lax'
            },
            body: JSON.stringify({ success: true })
        };
    }

    // 检查登录状态
    if (event.httpMethod === 'GET') {
        const token = event.headers.cookie?.match(/token=([^;]+)/)?.[1];
        if (token) {
            try {
                // 实际项目中应该验证token的完整性和过期时间
                return {
                    statusCode: 200,
                    headers: securityHeaders,
                    body: JSON.stringify({ 
                        success: true,
                        username: "管理员" // 从token解码获取
                    })
                };
            } catch {
                // token无效
            }
        }
        return {
            statusCode: 401,
            headers: securityHeaders,
            body: JSON.stringify({ success: false })
        };
    }

    // 处理登录请求
    if (event.httpMethod === 'POST') {
        const { username, password } = JSON.parse(event.body);
        
        // 验证凭证 - 实际项目应该使用加密比较
        if (username === process.env.ADMIN_USER && password === process.env.ADMIN_PASS) {
            // 生成更安全的token
            const token = Buffer.from(`${username}:${Date.now()}:${Math.random()}`).toString('base64');
            
            return {
                statusCode: 200,
                headers: {
                    ...securityHeaders,
                    'Set-Cookie': `token=${token}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=86400`
                },
                body: JSON.stringify({ 
                    success: true,
                    username
                })
            };
        }
        
        return {
            statusCode: 401,
            headers: securityHeaders,
            body: JSON.stringify({ success: false })
        };
    }

    return {
        statusCode: 405,
        headers: securityHeaders,
        body: JSON.stringify({ error: 'Method not allowed' })
    };
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
