#!/usr/bin/env node

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js"; 
import {
    isInitializeRequest, 
} from "@modelcontextprotocol/sdk/types.js";
import { google } from 'googleapis';
import { z } from "zod";
import { OAuth2Client } from 'google-auth-library';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import http from 'http';
import open from 'open';
import os from 'os';
import {createEmailMessage} from "./utl.js";
import { createLabel, updateLabel, deleteLabel, listLabels, findLabelByName, getOrCreateLabel, GmailLabel } from "./label-manager.js";
import express from "express";
import { Request, Response } from "express";
import { randomUUID } from "node:crypto"; // Use node:crypto for UUID
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// Configuration paths
const CONFIG_DIR = path.join(os.homedir(), '.gmail-mcp');
const OAUTH_PATH = process.env.GMAIL_OAUTH_PATH || path.join(CONFIG_DIR, 'gcp-oauth.keys.json');
const CREDENTIALS_PATH = process.env.GMAIL_CREDENTIALS_PATH || path.join(CONFIG_DIR, 'credentials.json');

// Type definitions for Gmail API responses (keep as is)
interface GmailMessagePart {
    partId?: string;
    mimeType?: string;
    filename?: string;
    headers?: Array<{
        name: string;
        value: string;
    }>;
    body?: {
        attachmentId?: string;
        size?: number;
        data?: string;
    };
    parts?: GmailMessagePart[];
}
interface EmailAttachment {
    id: string;
    filename: string;
    mimeType: string;
    size: number;
}
interface EmailContent {
    text: string;
    html: string;
}

// OAuth2 configuration (keep as is)
let oauth2Client: OAuth2Client;

// extractEmailContent function (keep as is)
function extractEmailContent(messagePart: GmailMessagePart): EmailContent {
    let textContent = '';
    let htmlContent = '';
    if (messagePart.body && messagePart.body.data) {
        const content = Buffer.from(messagePart.body.data, 'base64').toString('utf8');
        if (messagePart.mimeType === 'text/plain') {
            textContent = content;
        } else if (messagePart.mimeType === 'text/html') {
            htmlContent = content;
        }
    }
    if (messagePart.parts && messagePart.parts.length > 0) {
        for (const part of messagePart.parts) {
            const { text, html } = extractEmailContent(part);
            if (text) textContent += text;
            if (html) htmlContent += html;
        }
    }
    return { text: textContent, html: htmlContent };
}

// loadCredentials function (keep as is)
async function loadCredentials() {
     try {
        if (!process.env.GMAIL_OAUTH_PATH && !CREDENTIALS_PATH &&!fs.existsSync(CONFIG_DIR)) {
            fs.mkdirSync(CONFIG_DIR, { recursive: true });
        }
        const localOAuthPath = path.join(process.cwd(), 'gcp-oauth.keys.json');
        let oauthPath = OAUTH_PATH;
        if (fs.existsSync(localOAuthPath)) {
            fs.copyFileSync(localOAuthPath, OAUTH_PATH);
            console.log('OAuth keys found in current directory, copied to global config.');
        }
        if (!fs.existsSync(OAUTH_PATH)) {
            console.error('Error: OAuth keys file not found. Please place gcp-oauth.keys.json in current directory or', CONFIG_DIR);
            process.exit(1);
        }
        const keysContent = JSON.parse(fs.readFileSync(OAUTH_PATH, 'utf8'));
        const keys = keysContent.installed || keysContent.web;
        if (!keys) {
            console.error('Error: Invalid OAuth keys file format. File should contain either "installed" or "web" credentials.');
            process.exit(1);
        }
        const callback = process.argv[2] === 'auth' && process.argv[3] 
        ? process.argv[3] 
        : "http://localhost:3000/oauth2callback";
        oauth2Client = new OAuth2Client(
            keys.client_id,
            keys.client_secret,
            callback
        );
        if (fs.existsSync(CREDENTIALS_PATH)) {
            const credentials = JSON.parse(fs.readFileSync(CREDENTIALS_PATH, 'utf8'));
            oauth2Client.setCredentials(credentials);
        }
    } catch (error) {
        console.error('Error loading credentials:', error);
        process.exit(1);
    }
}

// authenticate function (keep as is)
async function authenticate() {
    const server = http.createServer();
    server.listen(3000);
    return new Promise<void>((resolve, reject) => {
        const authUrl = oauth2Client.generateAuthUrl({
            access_type: 'offline',
            scope: ['https://www.googleapis.com/auth/gmail.modify'],
        });
        console.log('Please visit this URL to authenticate:', authUrl);
        open(authUrl);
        server.on('request', async (req, res) => {
            if (!req.url?.startsWith('/oauth2callback')) return;
            const url = new URL(req.url, 'http://localhost:3000');
            const code = url.searchParams.get('code');
            if (!code) {
                res.writeHead(400);
                res.end('No code provided');
                reject(new Error('No code provided'));
                return;
            }
            try {
                const { tokens } = await oauth2Client.getToken(code);
                oauth2Client.setCredentials(tokens);
                fs.writeFileSync(CREDENTIALS_PATH, JSON.stringify(tokens));
                res.writeHead(200);
                res.end('Authentication successful! You can close this window.');
                server.close();
                resolve();
            } catch (error) {
                res.writeHead(500);
                res.end('Authentication failed');
                reject(error);
            }
        });
    });
}

// --- Schema Definitions (Keep all Zod schemas as they are) ---
const SendEmailSchema = z.object({
    to: z.array(z.string()).describe("List of recipient email addresses"),
    subject: z.string().describe("Email subject"),
    body: z.string().describe("Email body content"),
    cc: z.array(z.string()).optional().describe("List of CC recipients"),
    bcc: z.array(z.string()).optional().describe("List of BCC recipients"),
    threadId: z.string().optional().describe("Thread ID to reply to"),
    inReplyTo: z.string().optional().describe("Message ID being replied to"),
});
const ReadEmailSchema = z.object({
    messageId: z.string().describe("ID of the email message to retrieve"),
});
const SearchEmailsSchema = z.object({
    query: z.string().describe("Gmail search query (e.g., 'from:example@gmail.com')"),
    maxResults: z.number().optional().describe("Maximum number of results to return"),
});
const ModifyEmailSchema = z.object({
    messageId: z.string().describe("ID of the email message to modify"),
    labelIds: z.array(z.string()).optional().describe("[Deprecated] Use addLabelIds instead"), // Keep for potential backward compatibility, but mark as deprecated
    addLabelIds: z.array(z.string()).optional().describe("List of label IDs to add to the message"),
    removeLabelIds: z.array(z.string()).optional().describe("List of label IDs to remove from the message"),
});
const DeleteEmailSchema = z.object({
    messageId: z.string().describe("ID of the email message to delete"),
});
const ListEmailLabelsSchema = z.object({}).describe("Retrieves all available Gmail labels");
const CreateLabelSchema = z.object({
    name: z.string().describe("Name for the new label"),
    messageListVisibility: z.enum(['show', 'hide']).optional().describe("Whether to show or hide the label in the message list"),
    labelListVisibility: z.enum(['labelShow', 'labelShowIfUnread', 'labelHide']).optional().describe("Visibility of the label in the label list"),
}).describe("Creates a new Gmail label");
const UpdateLabelSchema = z.object({
    id: z.string().describe("ID of the label to update"),
    name: z.string().optional().describe("New name for the label"),
    messageListVisibility: z.enum(['show', 'hide']).optional().describe("Whether to show or hide the label in the message list"),
    labelListVisibility: z.enum(['labelShow', 'labelShowIfUnread', 'labelHide']).optional().describe("Visibility of the label in the label list"),
}).describe("Updates an existing Gmail label");
const DeleteLabelSchema = z.object({
    id: z.string().describe("ID of the label to delete"),
}).describe("Deletes a Gmail label");
const GetOrCreateLabelSchema = z.object({
    name: z.string().describe("Name of the label to get or create"),
    messageListVisibility: z.enum(['show', 'hide']).optional().describe("Whether to show or hide the label in the message list"),
    labelListVisibility: z.enum(['labelShow', 'labelShowIfUnread', 'labelHide']).optional().describe("Visibility of the label in the label list"),
}).describe("Gets an existing label by name or creates it if it doesn't exist");
const BatchModifyEmailsSchema = z.object({
    messageIds: z.array(z.string()).describe("List of message IDs to modify"),
    addLabelIds: z.array(z.string()).optional().describe("List of label IDs to add to all messages"),
    removeLabelIds: z.array(z.string()).optional().describe("List of label IDs to remove from all messages"),
    batchSize: z.number().optional().default(50).describe("Number of messages to process in each batch (default: 50)"),
});
const BatchDeleteEmailsSchema = z.object({
    messageIds: z.array(z.string()).describe("List of message IDs to delete"),
    batchSize: z.number().optional().default(50).describe("Number of messages to process in each batch (default: 50)"),
});
// --- End Schema Definitions ---

// Main function
async function main() {
    await loadCredentials();

    if (process.argv[2] === 'auth') {
        await authenticate();
        console.log('Authentication completed successfully');
        process.exit(0);
    }

    // Initialize Gmail API
    const gmail = google.gmail({ version: 'v1', auth: oauth2Client });

    // --- Initialize McpServer helper class --- 
    const server = new McpServer({
        name: "gmail",
        version: "1.0.0",
    });

    // --- Helper function for email sending/drafting --- 
    async function handleEmailAction(action: "send" | "draft", args: z.infer<typeof SendEmailSchema>) {
        const message = createEmailMessage(args);
        const encodedMessage = Buffer.from(message).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
        interface GmailMessageRequest { raw: string; threadId?: string; }
        const messageRequest: GmailMessageRequest = { raw: encodedMessage };
        if (args.threadId) { messageRequest.threadId = args.threadId; }
        if (args.inReplyTo) {
            // Note: createEmailMessage needs modification to include these headers properly
            console.warn("In-Reply-To handling requires modification in createEmailMessage to set headers");
        }
        if (action === "send") {
            const response = await gmail.users.messages.send({ userId: 'me', requestBody: messageRequest });
            return { content: [{ type: "text", text: `Email sent successfully with ID: ${response.data.id}` }] };
        } else {
            const response = await gmail.users.drafts.create({ userId: 'me', requestBody: { message: messageRequest } });
            return { content: [{ type: "text", text: `Email draft created successfully with ID: ${response.data.id}` }] };
        }
    }

    // --- Helper function for batch processing --- 
    async function processBatches<T, U>(
        items: T[],
        batchSize: number,
        processFn: (batch: T[]) => Promise<U[]>
    ): Promise<{ successes: U[], failures: { item: T, error: Error }[] }> {
        const successes: U[] = [];
        const failures: { item: T, error: Error }[] = [];
        for (let i = 0; i < items.length; i += batchSize) {
            const batch = items.slice(i, i + batchSize);
            try {
                const results = await processFn(batch);
                successes.push(...results);
            } catch (error) {
                console.error(`Batch failed (index ${i}):`, error); 
                for (const item of batch) {
                    try {
                        const result = await processFn([item]); 
                        successes.push(...result);
                    } catch (itemError) {
                        console.error(`Item failed within batch:`, item, itemError); 
                        failures.push({ item, error: itemError as Error });
                    }
                }
            }
        }
        return { successes, failures };
    }

    // --- Register Tools using server.tool() --- 

    server.tool("send_email", SendEmailSchema, async (args) => {
        try {
            return await handleEmailAction("send", args);
        } catch (error: any) { return { content: [{ type: "text", text: `Error sending email: ${error.message}` }], isError: true }; }
    });

    server.tool("draft_email", SendEmailSchema, async (args) => {
        try {
            return await handleEmailAction("draft", args);
        } catch (error: any) { return { content: [{ type: "text", text: `Error drafting email: ${error.message}` }], isError: true }; }
    });

    server.tool("read_email", ReadEmailSchema, async ({ messageId }) => {
        try {
            const response = await gmail.users.messages.get({
                userId: 'me',
                id: messageId,
                format: 'full',
            });
            const payload = response.data.payload;
            if (!payload) throw new Error("No payload found in message.");
            const headers = payload.headers || [];
            const subject = headers.find(h => h.name?.toLowerCase() === 'subject')?.value || '';
            const from = headers.find(h => h.name?.toLowerCase() === 'from')?.value || '';
            const to = headers.find(h => h.name?.toLowerCase() === 'to')?.value || '';
            const date = headers.find(h => h.name?.toLowerCase() === 'date')?.value || '';
            const threadId = response.data.threadId || '';
            const { text, html } = extractEmailContent(payload as GmailMessagePart);
            let body = text || html || '';
            const contentTypeNote = !text && html ? '[Note: This email is HTML-formatted. Plain text version not available.]\n\n' : '';
            const attachments: EmailAttachment[] = [];
            const processAttachmentParts = (part: GmailMessagePart) => {
                if (part.body && part.body.attachmentId && part.filename) { 
                    attachments.push({
                        id: part.body.attachmentId,
                        filename: part.filename,
                        mimeType: part.mimeType || 'application/octet-stream',
                        size: part.body.size || 0
                    });
                }
                if (part.parts) {
                    part.parts.forEach(processAttachmentParts);
                }
            };
            processAttachmentParts(payload as GmailMessagePart);
            const attachmentInfo = attachments.length > 0 ?
                `\n\nAttachments (${attachments.length}):\n` +
                attachments.map(a => `- ${a.filename} (${a.mimeType}, ${Math.round((a.size || 0) / 1024)} KB)`).join('\n') : '';
            return {
                content: [{ type: "text", text: `Thread ID: ${threadId}\nSubject: ${subject}\nFrom: ${from}\nTo: ${to}\nDate: ${date}\n\n${contentTypeNote}${body}${attachmentInfo}` }],
            };
        } catch (error: any) { return { content: [{ type: "text", text: `Error reading email: ${error.message}` }], isError: true }; }
    });

    server.tool("search_emails", SearchEmailsSchema, async ({ query, maxResults }) => {
        try {
            const response = await gmail.users.messages.list({
                userId: 'me',
                q: query,
                maxResults: maxResults || 10,
            });
            const messages = response.data.messages || [];
            if (messages.length === 0) {
                 return { content: [{ type: "text", text: "No messages found matching the query." }] };
            }
            const results = await Promise.all(
                messages.map(async (msg) => {
                    if (!msg.id) return null;
                    try {
                         const detail = await gmail.users.messages.get({
                            userId: 'me',
                            id: msg.id,
                            format: 'metadata',
                            metadataHeaders: ['Subject', 'From', 'Date'],
                        });
                        const headers = detail.data.payload?.headers || [];
                        return {
                            id: msg.id,
                            subject: headers.find(h => h.name?.toLowerCase() === 'subject')?.value || '(No Subject)',
                            from: headers.find(h => h.name?.toLowerCase() === 'from')?.value || '(Unknown Sender)',
                            date: headers.find(h => h.name?.toLowerCase() === 'date')?.value || '(Unknown Date)',
                        };
                    } catch (detailError) {
                        console.error(`Failed to get details for message ${msg.id}:`, detailError);
                        return { id: msg.id, subject: '(Error fetching details)', from: '', date: '' }; 
                    }
                })
            );
            const validResults = results.filter(r => r !== null);
             if (validResults.length === 0) {
                 return { content: [{ type: "text", text: "No messages found or details could not be retrieved." }] };
            }
            return {
                content: [{ type: "text", text: "Found messages:\n" + validResults.map(r => `ID: ${r!.id}\nSubject: ${r!.subject}\nFrom: ${r!.from}\nDate: ${r!.date}\n`).join('\n') }],
            };
        } catch (error: any) { return { content: [{ type: "text", text: `Error searching emails: ${error.message}` }], isError: true }; }
    });

    server.tool("modify_email", ModifyEmailSchema, async (args) => {
        try {
            const requestBody: { addLabelIds?: string[]; removeLabelIds?: string[] } = {};
            if (args.addLabelIds && args.addLabelIds.length > 0) {
                requestBody.addLabelIds = args.addLabelIds;
            } else if (args.labelIds && args.labelIds.length > 0) {
                 console.warn("Using deprecated 'labelIds' for adding labels. Prefer 'addLabelIds'.");
                 requestBody.addLabelIds = args.labelIds;
            }
            if (args.removeLabelIds && args.removeLabelIds.length > 0) {
                requestBody.removeLabelIds = args.removeLabelIds;
            }
            if (!requestBody.addLabelIds && !requestBody.removeLabelIds) {
                throw new Error("No labels provided to add or remove.");
            }
            await gmail.users.messages.modify({
                userId: 'me',
                id: args.messageId,
                requestBody: requestBody,
            });
            return { content: [{ type: "text", text: `Email ${args.messageId} labels updated successfully` }] };
        } catch (error: any) { return { content: [{ type: "text", text: `Error modifying email: ${error.message}` }], isError: true }; }
    });

    server.tool("delete_email", DeleteEmailSchema, async ({ messageId }) => {
        try {
            await gmail.users.messages.delete({ userId: 'me', id: messageId });
            return { content: [{ type: "text", text: `Email ${messageId} deleted successfully` }] };
        } catch (error: any) { return { content: [{ type: "text", text: `Error deleting email: ${error.message}` }], isError: true }; }
    });

    server.tool("list_email_labels", ListEmailLabelsSchema, async () => {
        try {
             const labelResults = await listLabels(gmail);
             const systemLabels = labelResults.system;
             const userLabels = labelResults.user;
             let text = `Found ${labelResults.count.total} labels (${labelResults.count.system} system, ${labelResults.count.user} user):\n\n`;
             if (systemLabels.length > 0) {
                text += "System Labels:\n" + systemLabels.map((l: GmailLabel) => `- ${l.name} (ID: ${l.id})`).join('\n') + "\n\n";
             }
             if (userLabels.length > 0) {
                 text += "User Labels:\n" + userLabels.map((l: GmailLabel) => `- ${l.name} (ID: ${l.id})`).join('\n');
             }
             return { content: [{ type: "text", text: text.trim() }] };
        } catch (error: any) { return { content: [{ type: "text", text: `Error listing labels: ${error.message}` }], isError: true }; }
    });
    
    server.tool("batch_modify_emails", BatchModifyEmailsSchema, async (args) => {
        try {
            const requestBody: { addLabelIds?: string[]; removeLabelIds?: string[] } = {};
            if (args.addLabelIds) requestBody.addLabelIds = args.addLabelIds;
            if (args.removeLabelIds) requestBody.removeLabelIds = args.removeLabelIds;
            if (!requestBody.addLabelIds && !requestBody.removeLabelIds) {
                 throw new Error("No labels provided to add or remove in batch.");
            }
            const { successes, failures } = await processBatches(
                args.messageIds,
                args.batchSize || 50,
                async (batch) => {
                    const res = await gmail.users.messages.batchModify({
                        userId: 'me',
                        requestBody: {
                            ids: batch,
                            ...(requestBody.addLabelIds && { addLabelIds: requestBody.addLabelIds }),
                            ...(requestBody.removeLabelIds && { removeLabelIds: requestBody.removeLabelIds }),
                        }
                    });
                    return batch.map(id => ({ messageId: id, success: true }));
                }
            );
            let resultText = `Batch label modification complete.\n`;
            resultText += `Attempted: ${args.messageIds.length} messages.\n`;
            resultText += `Batches resulting in success: ${successes.length}\n`; 
            if (failures.length > 0) {
                resultText += `Batches/Items resulting in failure: ${failures.length}\n`;
                resultText += `Failed item IDs/Errors (first few shown):\n`;
                resultText += failures.slice(0, 5).map(f => `- Item: ${JSON.stringify(f.item)}, Error: ${f.error.message}`).join('\n');
            }
            return { content: [{ type: "text", text: resultText }] };
        } catch (error: any) { return { content: [{ type: "text", text: `Error in batch modify: ${error.message}` }], isError: true }; }
    });

    server.tool("batch_delete_emails", BatchDeleteEmailsSchema, async (args) => {
        try {
             const { successes, failures } = await processBatches(
                args.messageIds,
                args.batchSize || 50,
                async (batch) => {
                    await gmail.users.messages.batchDelete({
                        userId: 'me',
                        requestBody: {
                            ids: batch,
                        }
                    });
                    return batch.map(id => ({ messageId: id, success: true }));
                }
            );
             let resultText = `Batch delete operation complete.\n`;
             resultText += `Attempted: ${args.messageIds.length} messages.\n`;
             resultText += `Batches resulting in success: ${successes.length}\n`;
             if (failures.length > 0) {
                resultText += `Batches/Items resulting in failure: ${failures.length}\n`;
                resultText += `Failed item IDs/Errors (first few shown):\n`;
                resultText += failures.slice(0, 5).map(f => `- Item: ${JSON.stringify(f.item)}, Error: ${f.error.message}`).join('\n');
             }
            return { content: [{ type: "text", text: resultText }] };
        } catch (error: any) { return { content: [{ type: "text", text: `Error in batch delete: ${error.message}` }], isError: true }; }
    });

    server.tool("create_label", CreateLabelSchema, async (args) => {
        try {
             const result = await createLabel(gmail, args.name, {
                 messageListVisibility: args.messageListVisibility,
                 labelListVisibility: args.labelListVisibility,
             });
             return { content: [{ type: "text", text: `Label created successfully:\nID: ${result.id}\nName: ${result.name}\nType: ${result.type}` }] };
        } catch (error: any) { return { content: [{ type: "text", text: `Error creating label: ${error.message}` }], isError: true }; }
    });

    server.tool("update_label", UpdateLabelSchema, async (args) => {
         try {
            const updates: Partial<GmailLabel> = {}; 
            if (args.name) updates.name = args.name;
            if (args.messageListVisibility) updates.messageListVisibility = args.messageListVisibility;
            if (args.labelListVisibility) updates.labelListVisibility = args.labelListVisibility;
            if (Object.keys(updates).length === 0) {
                throw new Error("No update fields provided for the label.");
            }
            const result = await updateLabel(gmail, args.id, updates);
            return { content: [{ type: "text", text: `Label updated successfully:\nID: ${result.id}\nName: ${result.name}\nType: ${result.type}` }] };
        } catch (error: any) { return { content: [{ type: "text", text: `Error updating label: ${error.message}` }], isError: true }; }
    });

    server.tool("delete_label", DeleteLabelSchema, async ({ id }) => {
        try {
            const result = await deleteLabel(gmail, id);
            return { content: [{ type: "text", text: result.message }] };
        } catch (error: any) { return { content: [{ type: "text", text: `Error deleting label: ${error.message}` }], isError: true }; }
    });

    server.tool("get_or_create_label", GetOrCreateLabelSchema, async (args) => {
        try {
            // Need to adjust getOrCreateLabel to return a structure indicating creation status
            const result = await getOrCreateLabel(gmail, args.name, { 
                messageListVisibility: args.messageListVisibility,
                labelListVisibility: args.labelListVisibility,
            });
            // Assuming getOrCreateLabel returns { label: GmailLabel, created: boolean }
            const action = result.created ? 'created new' : 'found existing'; 
            return { content: [{ type: "text", text: `Successfully ${action} label:\nID: ${result.label.id}\nName: ${result.label.name}\nType: ${result.label.type}` }] };
        } catch (error: any) { return { content: [{ type: "text", text: `Error getting or creating label: ${error.message}` }], isError: true }; }
    });
    // --- End Tool Registration ---

    // --- Keep Stateful Streamable HTTP Transport Setup --- 
    const app = express();
    app.use(express.json()); 
    const port = process.env.PORT || 3000;
    const transports: { [sessionId: string]: StreamableHTTPServerTransport } = {};
    app.all('/mcp', async (req: Request, res: Response) => {
        const sessionId = req.headers['mcp-session-id'] as string | undefined;
        let transport: StreamableHTTPServerTransport;
        if (sessionId && transports[sessionId]) {
            transport = transports[sessionId];
        } else if (!sessionId && req.method === 'POST' && isInitializeRequest(req.body)) {
            transport = new StreamableHTTPServerTransport({
                sessionIdGenerator: randomUUID,
                onsessioninitialized: (newSessionId) => { transports[newSessionId] = transport; },
            });
            transport.onclose = () => { if (transport.sessionId) delete transports[transport.sessionId]; };
            await server.connect(transport);
        } else {
            res.status(400).json({ error: 'Bad Request' });
            return;
        }
        try {
            const requestBody = req.method === 'POST' ? req.body : undefined;
            await transport.handleRequest(req, res, requestBody);
        } catch (error) {
            console.error(`Error handling MCP request for session ${transport.sessionId}:`, error);
            if (!res.headersSent) res.status(500).json({ error: 'Internal server error' });
        }
    });
    app.listen(port, () => {
        console.log(`Gmail MCP Server (Stateful Streamable HTTP) listening on port ${port}, endpoint /mcp`);
    });
}

main().catch((error) => {
    console.error('Server fatal error:', error);
    process.exit(1);
});