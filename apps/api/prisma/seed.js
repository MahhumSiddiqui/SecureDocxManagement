import 'dotenv/config';
import argon2 from 'argon2';
import { PrismaClient } from '@prisma/client';
import { randomUUID } from 'node:crypto';
import { mkdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { encryptBuffer } from '../src/services/crypto.service.js';
const prisma = new PrismaClient();
const password = 'Passw0rd!Demo';
async function main() { const hash = await argon2.hash(password, { type: argon2.argon2id, memoryCost: 19456, timeCost: 2, parallelism: 1 }); const users = await Promise.all([['admin@securedocs.test', 'Admin', 'ADMINISTRATOR'], ['auditor@securedocs.test', 'Auditor', 'AUDITOR'], ['owner@securedocs.test', 'Owner', 'DOCUMENT_OWNER'], ['user@securedocs.test', 'User', 'STANDARD_USER']].map(([email, displayName, role]) => prisma.user.upsert({ where: { email }, update: {}, create: { email, displayName, passwordHash: hash, role: role } }))); const owner = users[2], grantee = users[3]; const storage = path.resolve(process.env.STORAGE_PATH ?? './storage/blobs'); await mkdir(storage, { recursive: true }); for (let i = 1; i <= 3; i++) {
    const plain = Buffer.from(`Synthetic SecureDocs document ${i}\n`);
    const enc = encryptBuffer(plain), storageKey = randomUUID();
    await writeFile(path.join(storage, storageKey), enc.ciphertext);
    const d = await prisma.document.upsert({ where: { storageKey }, update: {}, create: { title: `Synthetic document ${i}`, originalName: `document-${i}.txt`, mimeType: 'text/plain', sizeBytes: plain.length, storageKey, sha256: enc.sha256, ownerId: owner.id, scanVerdict: 'CLEAN', key: { create: { wrappedDek: enc.wrappedDek, iv: enc.iv, authTag: enc.authTag, wrapIv: enc.wrapIv, wrapTag: enc.wrapTag } } } });
    if (i === 1)
        await prisma.documentPermission.upsert({ where: { documentId_granteeId: { documentId: d.id, granteeId: grantee.id } }, update: {}, create: { documentId: d.id, granteeId: grantee.id, grantedById: owner.id, canView: true, canDownload: true } });
} console.log('Seeded SecureDocs users and documents.'); }
main().finally(() => prisma.$disconnect());
