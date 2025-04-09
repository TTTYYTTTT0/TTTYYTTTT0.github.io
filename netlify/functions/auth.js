exports.handler = async (event) => {
    // 处理退出登录请求
    if (event.httpMethod === 'DELETE') {
        return {
            statusCode: 200,
            headers: {
                'Set-Cookie': 'token=; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly; Secure; SameSite=Lax'
            },
            body: JSON.stringify({ success: true })
        };
    }
    
    // 检查是否已登录 (GET 请求)
    if (event.httpMethod === 'GET') {
        const cookies = event.headers.cookie || '';
        const token = cookies.split(';').find(c => c.trim().startsWith('token='))?.split('=')[1];
        
        // 只要存在未过期的 token 就认为有效（简化示例）
        // 实际生产环境应该验证 token 内容和过期时间
        if (token) {
            return {
                statusCode: 200,
                body: JSON.stringify({ 
                    success: true,
                    username: process.env.ADMIN_USER // 返回用户名用于前端显示
                })
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
            // 生成包含过期时间的 token（24小时后过期）
            const token = JSON.stringify({
                user: username,
                exp: Date.now() + 86400000 // 24小时
            });
            const encryptedToken = Buffer.from(token).toString('base64');
            
            return {
                statusCode: 200,
                headers: {
                    'Set-Cookie': `token=${encryptedToken}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=86400`
                },
                body: JSON.stringify({ 
                    success: true,
                    username: username
                })
            };
        } else {
            return {
                statusCode: 401,
                body: JSON.stringify({ 
                    success: false, 
                    error: '用户名或密码错误' 
                })
            };
        }
    }
    
    return {
        statusCode: 405,
        body: JSON.stringify({ error: 'Method not allowed' })
    };
};
