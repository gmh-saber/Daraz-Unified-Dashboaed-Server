// backend/server.ts
// FIX: Explicitly use express.Request and express.Response types to avoid conflicts with global types.
import express from 'express';
import cors from 'cors';
import crypto from 'crypto';
import fetch from 'node-fetch';
import 'dotenv/config';

const app = express();
app.use(cors({ origin: 'http://localhost:3000' }));
// FIX: Pass an empty options object to express.json() to help with TypeScript overload resolution.
app.use(express.json({}));

const PORT = process.env.PORT || 8080;
const APP_KEY = process.env.APP_KEY;
const APP_SECRET = process.env.APP_SECRET;
const FRONTEND_URL = process.env.FRONTEND_URL || 'http://localhost:3000';

// In-memory storage for simplicity. In production, use a database.
let accounts: { [id: string]: any } = {};

// FIX: Define an interface for Daraz API responses to avoid 'unknown' type issues.
interface DarazResponse<T = any> {
    code: string;
    message?: string;
    data?: T;
}

const API_BASE_URL = 'https://api.daraz.com.bd/rest';
const AUTH_URL = 'https://api.daraz.com.bd/oauth/authorize';

// --- UTILITY: API SIGNING ---
const signRequest = (path: string, params: Record<string, any>, secret: string): string => {
    const sortedKeys = Object.keys(params).sort();
    const concatenatedString = sortedKeys.map(key => `${key}${params[key]}`).join('');
    const stringToSign = `${path}${concatenatedString}`;
    return crypto.createHmac('sha256', secret).update(stringToSign).digest('hex').toUpperCase();
};

// --- AUTHENTICATION FLOW ---

// FIX: Use express.Request and express.Response types to avoid ambiguity with global types.
app.get('/api/auth/initiate', (req: express.Request, res: express.Response) => {
    if (!APP_KEY) {
        return res.status(500).send("App Key is not configured on the backend.");
    }
    // The redirect URI must point to *this backend's* callback endpoint.
    const redirectUri = `${req.protocol}://${req.get('host')}/api/auth/callback`;
    
    const params = new URLSearchParams({
        response_type: 'code',
        force_auth: 'true',
        redirect_uri: redirectUri,
        client_id: APP_KEY,
    });
    res.redirect(`${AUTH_URL}?${params.toString()}`);
});

// FIX: Use express.Request and express.Response types to avoid ambiguity with global types.
app.get('/api/auth/callback', async (req: express.Request, res: express.Response) => {
    const { code } = req.query;

    if (!code || typeof code !== 'string') {
        return res.status(400).send("Authorization code is missing.");
    }
    if (!APP_KEY || !APP_SECRET) {
        return res.status(500).send("Backend is not configured with App credentials.");
    }

    try {
        const path = '/auth/token/create';
        const params = {
            app_key: APP_KEY,
            app_secret: APP_SECRET,
            sign_method: 'sha256',
            timestamp: `${Date.now()}`,
            code: code,
        };

        const signature = signRequest(path, params, APP_SECRET);
        
        const formData = new URLSearchParams();
        for (const key in params) {
            formData.append(key, params[key]);
        }
        formData.append('sign', signature);
        
        const response = await fetch(`${API_BASE_URL}${path}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8' },
            body: formData,
        });

        // FIX: Cast the JSON response to the defined interface to fix property access errors on 'unknown'.
        const result = await response.json() as DarazResponse;

        if (result.code !== '0') {
            throw new Error(`Daraz API Error: ${result.message}`);
        }

        const tokenData = result.data;
        const sellerInfo = tokenData.country_user_info[0];

        // Store the account details and tokens
        accounts[sellerInfo.seller_id] = {
            id: sellerInfo.seller_id,
            name: sellerInfo.short_code,
            logoUrl: 'https://img.uxwing.com/wp-content/themes/uxwing/download/brands-social-media/daraz-logo-icon.png',
            accessToken: tokenData.access_token,
            refreshToken: tokenData.refresh_token,
            accessTokenExpire: Date.now() + (tokenData.expires_in * 1000),
        };
        
        console.log("Successfully added account:", sellerInfo.short_code);

        // Redirect back to the frontend settings page
        res.redirect(FRONTEND_URL);

    } catch (error) {
        console.error("Failed to exchange code for token:", error);
        res.status(500).redirect(`${FRONTEND_URL}?auth_error=${encodeURIComponent((error as Error).message)}`);
    }
});

// --- API PROXY ENDPOINTS ---

const performSignedRequest = async (path: string, accountId: string, extraParams: Record<string, any> = {}, method = 'GET') => {
    const account = accounts[accountId];
    if (!account || !account.accessToken) {
        throw new Error(`No valid token for account ${accountId}`);
    }

    // TODO: Add logic here to use refresh_token if access_token is expired.

    const commonParams = {
        app_key: APP_KEY,
        access_token: account.accessToken,
        sign_method: 'sha256',
        timestamp: `${Date.now()}`,
    };
    
    const allParams = { ...commonParams, ...extraParams };
    const signature = signRequest(path, allParams, APP_SECRET!);

    const queryParams = new URLSearchParams({ ...allParams, sign: signature });
    const url = `${API_BASE_URL}${path}?${queryParams.toString()}`;

    const response = await fetch(url, { method });
    // FIX: Cast the JSON response to the defined interface to fix property access errors on 'unknown'.
    const result = await response.json() as DarazResponse;

    if (result.code !== '0') {
        throw new Error(`Daraz API Error: ${result.message}`);
    }

    return result.data;
};

// FIX: Use express.Request and express.Response types to avoid ambiguity with global types.
app.get('/api/accounts', (req: express.Request, res: express.Response) => {
    // Return public-safe account info, excluding tokens
    const publicAccounts = Object.values(accounts).map(({ id, name, logoUrl }) => ({ id, name, logoUrl }));
    res.json(publicAccounts);
});

// FIX: Use express.Request and express.Response types to avoid ambiguity with global types.
app.post('/api/accounts/disconnect', (req: express.Request, res: express.Response) => {
    const { accountId } = req.body;
    if (accounts[accountId]) {
        delete accounts[accountId];
        res.status(200).json({ success: true });
    } else {
        res.status(404).json({ success: false, message: "Account not found" });
    }
});

// FIX: Use express.Request and express.Response types to avoid ambiguity with global types.
app.get('/api/orders', async (req: express.Request, res: express.Response) => {
    try {
        let allOrders: any[] = [];
        const thirtyDaysAgo = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString();

        for (const accountId in accounts) {
            const account = accounts[accountId];
            const data = await performSignedRequest('/orders/get', accountId, {
                create_after: thirtyDaysAgo,
                limit: '100',
                offset: '0',
            });
            if (data && data.orders) {
                const transformed = data.orders.map((o: any) => ({ ...o, account: { id: account.id, name: account.name, logoUrl: account.logoUrl } }));
                allOrders = [...allOrders, ...transformed];
            }
        }
        res.json(allOrders);
    } catch (error) {
        res.status(500).json({ error: (error as Error).message });
    }
});

// FIX: Use express.Request and express.Response types to avoid ambiguity with global types.
app.get('/api/financials', async (req: express.Request, res: express.Response) => {
     try {
        let allFinancials: any[] = [];
        for (const accountId in accounts) {
            const account = accounts[accountId];
            const data = await performSignedRequest('/finance/payout/status/get', accountId);
            if (data) {
                allFinancials.push({
                    account: { id: account.id, name: account.name, logoUrl: account.logoUrl },
                    ...data
                });
            }
        }
        res.json(allFinancials);
    } catch (error) {
        res.status(500).json({ error: (error as Error).message });
    }
});

// FIX: Use express.Request and express.Response types to avoid ambiguity with global types.
app.post('/api/pack', async (req: express.Request, res: express.Response) => {
    try {
        const { orderItemIds, accountId } = req.body;
        if (!orderItemIds || !accountId) {
            return res.status(400).json({ error: 'Missing orderItemIds or accountId' });
        }
        
        // Daraz API requires this to be a stringified JSON array
        const orderItemIdsString = JSON.stringify(orderItemIds);

        const data = await performSignedRequest('/order/rts', accountId, {
            order_item_ids: orderItemIdsString,
            delivery_type: 'dropship',
            shipping_provider: 'BD-DEX',
        }, 'POST');
        
        res.json(data);

    } catch(error) {
        res.status(500).json({ error: (error as Error).message });
    }
});


app.listen(PORT, () => {
    console.log(`Backend server running on http://localhost:${PORT}`);
    if (!APP_KEY || !APP_SECRET) {
        console.warn("WARNING: APP_KEY or APP_SECRET is not set in the .env file. The application will not be able to authenticate with Daraz.");
    }
});
