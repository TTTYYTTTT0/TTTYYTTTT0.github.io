exports.handler = async (event) => {
    // 处理退出登录请求
    if (event.httpMethod === 'DELETE') {
        return {
            statusCode: 200,
            headers: {
                'Set-Cookie': 'token=; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT'
            },
            body: JSON.stringify({ success: true })
        };
    }
    
    // 检查是否已登录 (GET 请求)
    if (event.httpMethod === 'GET') {
        const token = event.headers.cookie?.split(';').find(c => c.trim().startsWith('token='))?.split('=')[1];
        
        if (token === process.env.ADMIN_TOKEN) {
            return {
                statusCode: 200,
                body: JSON.stringify({ success: true })
            };
        } else {
            return {
                statusCode: 401,
                body: JSON.stringify({ success: false })
            };
        }
    }
    
    // 处理登录请求 (POST 请求)
    if (event.httpMethod === 'POST') {
        const { username, password } = JSON.parse(event.body);
        
        if (username === process.env.ADMIN_USER && password === process.env.ADMIN_PASS) {
            // 生成一个简单的 token (实际应用中应该使用更安全的方案)
            const token = Buffer.from(`${username}:${Date.now()}`).toString('base64');
            
            return {
                statusCode: 200,
                headers: {
                    'Set-Cookie': `token=${token}; Path=/; HttpOnly; Secure; SameSite=Strict`
                },
                body: JSON.stringify({ success: true })
            };
        } else {
            return {
                statusCode: 401,
                body: JSON.stringify({ success: false, error: 'Invalid credentials' })
            };
        }
    }
    
    return {
        statusCode: 405,
        body: JSON.stringify({ error: 'Method not allowed' })
    };
};
