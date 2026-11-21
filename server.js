
'use strict';

require('dotenv').config();

const express = require('express');
const multer = require('multer');
const AdmZip = require('adm-zip');
const crypto = require('crypto');
const fs = require('fs');
const fsp = fs.promises;
const path = require('path');
const os = require('os');
const zlib = require('zlib');
const { execFile, spawn } = require('child_process');
const { promisify } = require('util');

const execFileAsync = promisify(execFile);

// ============================================================================
// Configuration & Constants
// ============================================================================

const PORT = parseInt(process.env.PORT || '3000', 10);
const MAX_APK_SIZE_BYTES = 20 * 1024 * 1024; // 20 MB hard limit
const MAX_ZIP_UPLOAD_BYTES = parseInt(process.env.MAX_ZIP_UPLOAD_BYTES || String(50 * 1024 * 1024), 10);
const MAX_EXTRACTED_SIZE_BYTES = parseInt(process.env.MAX_EXTRACTED_SIZE_BYTES || String(120 * 1024 * 1024), 10);
const MAX_EXTRACTED_FILES = parseInt(process.env.MAX_EXTRACTED_FILES || '5000', 10);
const BUILD_TIMEOUT_MS = parseInt(process.env.BUILD_TIMEOUT_MS || String(5 * 60 * 1000), 10);
const APK_EXPIRATION_MS = parseInt(process.env.APK_EXPIRATION_MINUTES || '30', 10) * 60 * 1000;
const KEYSTORE_EXPIRATION_MS = parseInt(process.env.KEYSTORE_EXPIRATION_MINUTES || '60', 10) * 60 * 1000;
const CLEANUP_INTERVAL_MS = 5 * 60 * 1000;
const GRADLE_MAX_HEAP = process.env.GRADLE_MAX_HEAP || '1024m';
const GRADLE_NO_DAEMON = process.env.GRADLE_NO_DAEMON !== 'false';

const WORK_ROOT = path.join(os.tmpdir(), 'apk-build-server');
const UPLOADS_DIR = path.join(WORK_ROOT, 'uploads');
const BUILDS_DIR = path.join(WORK_ROOT, 'builds');
const KEYSTORES_DIR = path.join(WORK_ROOT, 'keystores');

const SECURITY_LIMITATION_NOTE =
  'Security Notice: AES-256-GCM protects packaged assets at rest inside the APK, and runtime decryption occurs inside the application process. Encryption raises reverse-engineering difficulty but does NOT make extraction impossible. Similarly, any API keys or secrets embedded in client-side HTML/CSS/JavaScript can be extracted from APKs at runtime or via reverse engineering; sensitive secrets should always remain on a secure backend server.';

const KEYSTORE_LOSS_WARNING =
  'Important Warning: Store your keystore file, alias, and passwords safely. Losing your signing keystore or credentials will prevent you from publishing future updates to the same application identity on Android/Google Play.';

// In-memory state stores
const builds = new Map();
const keystores = new Map();
let isShuttingDown = false;
const activeChildProcesses = new Set();

// Ensure base work directories exist
for (const dir of [WORK_ROOT, UPLOADS_DIR, BUILDS_DIR, KEYSTORES_DIR]) {
  fs.mkdirSync(dir, { recursive: true });
}

// ============================================================================
// Supported Android Permissions Catalog
// ============================================================================

const SUPPORTED_PERMISSIONS = [
  {
    id: 'android.permission.INTERNET',
    name: 'INTERNET',
    category: 'network',
    protectionLevel: 'normal',
    runtime: false,
    minSdk: 1,
    maxSdk: null,
    description: 'Allows opening network sockets and loading external web resources.'
  },
  {
    id: 'android.permission.ACCESS_NETWORK_STATE',
    name: 'ACCESS_NETWORK_STATE',
    category: 'network',
    protectionLevel: 'normal',
    runtime: false,
    minSdk: 1,
    maxSdk: null,
    description: 'Allows accessing information about network connectivity.'
  },
  {
    id: 'android.permission.ACCESS_WIFI_STATE',
    name: 'ACCESS_WIFI_STATE',
    category: 'network',
    protectionLevel: 'normal',
    runtime: false,
    minSdk: 1,
    maxSdk: null,
    description: 'Allows accessing information about Wi-Fi networks.'
  },
  {
    id: 'android.permission.CAMERA',
    name: 'CAMERA',
    category: 'hardware',
    protectionLevel: 'dangerous',
    runtime: true,
    minSdk: 1,
    maxSdk: null,
    usesFeature: 'android.hardware.camera',
    description: 'Required to access the device camera (e.g. WebRTC or file capture).'
  },
  {
    id: 'android.permission.RECORD_AUDIO',
    name: 'RECORD_AUDIO',
    category: 'hardware',
    protectionLevel: 'dangerous',
    runtime: true,
    minSdk: 1,
    maxSdk: null,
    usesFeature: 'android.hardware.microphone',
    description: 'Allows recording audio via microphone.'
  },
  {
    id: 'android.permission.MODIFY_AUDIO_SETTINGS',
    name: 'MODIFY_AUDIO_SETTINGS',
    category: 'hardware',
    protectionLevel: 'normal',
    runtime: false,
    minSdk: 1,
    maxSdk: null,
    description: 'Allows modifying global audio settings.'
  },
  {
    id: 'android.permission.ACCESS_FINE_LOCATION',
    name: 'ACCESS_FINE_LOCATION',
    category: 'location',
    protectionLevel: 'dangerous',
    runtime: true,
    minSdk: 1,
    maxSdk: null,
    usesFeature: 'android.hardware.location.gps',
    description: 'Allows accessing precise GPS location.'
  },
  {
    id: 'android.permission.ACCESS_COARSE_LOCATION',
    name: 'ACCESS_COARSE_LOCATION',
    category: 'location',
    protectionLevel: 'dangerous',
    runtime: true,
    minSdk: 1,
    maxSdk: null,
    usesFeature: 'android.hardware.location.network',
    description: 'Allows accessing approximate network-based location.'
  },
  {
    id: 'android.permission.READ_EXTERNAL_STORAGE',
    name: 'READ_EXTERNAL_STORAGE',
    category: 'media',
    protectionLevel: 'dangerous',
    runtime: true,
    minSdk: 16,
    maxSdk: 32,
    description: 'Reads shared storage on Android 12L (API 32) and below.'
  },
  {
    id: 'android.permission.WRITE_EXTERNAL_STORAGE',
    name: 'WRITE_EXTERNAL_STORAGE',
    category: 'media',
    protectionLevel: 'dangerous',
    runtime: true,
    minSdk: 4,
    maxSdk: 28,
    description: 'Writes to shared storage on Android 9 (API 28) and below.'
  },
  {
    id: 'android.permission.READ_MEDIA_IMAGES',
    name: 'READ_MEDIA_IMAGES',
    category: 'media',
    protectionLevel: 'dangerous',
    runtime: true,
    minSdk: 33,
    maxSdk: null,
    description: 'Reads image files from external storage on Android 13+ (API 33+).'
  },
  {
    id: 'android.permission.READ_MEDIA_VIDEO',
    name: 'READ_MEDIA_VIDEO',
    category: 'media',
    protectionLevel: 'dangerous',
    runtime: true,
    minSdk: 33,
    maxSdk: null,
    description: 'Reads video files from external storage on Android 13+ (API 33+).'
  },
  {
    id: 'android.permission.READ_MEDIA_AUDIO',
    name: 'READ_MEDIA_AUDIO',
    category: 'media',
    protectionLevel: 'dangerous',
    runtime: true,
    minSdk: 33,
    maxSdk: null,
    description: 'Reads audio files from external storage on Android 13+ (API 33+).'
  },
  {
    id: 'android.permission.POST_NOTIFICATIONS',
    name: 'POST_NOTIFICATIONS',
    category: 'notifications',
    protectionLevel: 'dangerous',
    runtime: true,
    minSdk: 33,
    maxSdk: null,
    description: 'Allows posting notifications on Android 13+ (API 33+).'
  },
  {
    id: 'android.permission.VIBRATE',
    name: 'VIBRATE',
    category: 'hardware',
    protectionLevel: 'normal',
    runtime: false,
    minSdk: 1,
    maxSdk: null,
    description: 'Allows access to the vibrator.'
  },
  {
    id: 'android.permission.WAKE_LOCK',
    name: 'WAKE_LOCK',
    category: 'system',
    protectionLevel: 'normal',
    runtime: false,
    minSdk: 1,
    maxSdk: null,
    description: 'Allows keeping processor or screen awake.'
  },
  {
    id: 'android.permission.BLUETOOTH',
    name: 'BLUETOOTH',
    category: 'bluetooth',
    protectionLevel: 'normal',
    runtime: false,
    minSdk: 1,
    maxSdk: 30,
    usesFeature: 'android.hardware.bluetooth',
    description: 'Connects to paired Bluetooth devices on Android 11 (API 30) and below.'
  },
  {
    id: 'android.permission.BLUETOOTH_ADMIN',
    name: 'BLUETOOTH_ADMIN',
    category: 'bluetooth',
    protectionLevel: 'normal',
    runtime: false,
    minSdk: 1,
    maxSdk: 30,
    usesFeature: 'android.hardware.bluetooth',
    description: 'Discovers and pairs Bluetooth devices on Android 11 (API 30) and below.'
  },
  {
    id: 'android.permission.BLUETOOTH_CONNECT',
    name: 'BLUETOOTH_CONNECT',
    category: 'bluetooth',
    protectionLevel: 'dangerous',
    runtime: true,
    minSdk: 31,
    maxSdk: null,
    usesFeature: 'android.hardware.bluetooth',
    description: 'Connects to paired Bluetooth devices on Android 12+ (API 31+).'
  },
  {
    id: 'android.permission.BLUETOOTH_SCAN',
    name: 'BLUETOOTH_SCAN',
    category: 'bluetooth',
    protectionLevel: 'dangerous',
    runtime: true,
    minSdk: 31,
    maxSdk: null,
    usesFeature: 'android.hardware.bluetooth',
    description: 'Discovers nearby Bluetooth devices on Android 12+ (API 31+).'
  },
  {
    id: 'android.permission.NFC',
    name: 'NFC',
    category: 'hardware',
    protectionLevel: 'normal',
    runtime: false,
    minSdk: 9,
    maxSdk: null,
    usesFeature: 'android.hardware.nfc',
    description: 'Allows I/O operations over NFC.'
  },
  {
    id: 'android.permission.USE_BIOMETRIC',
    name: 'USE_BIOMETRIC',
    category: 'sensors',
    protectionLevel: 'normal',
    runtime: false,
    minSdk: 28,
    maxSdk: null,
    description: 'Allows using device biometric hardware.'
  },
  {
    id: 'android.permission.READ_CONTACTS',
    name: 'READ_CONTACTS',
    category: 'personal',
    protectionLevel: 'dangerous',
    runtime: true,
    minSdk: 1,
    maxSdk: null,
    description: 'Allows reading the user contacts data.'
  },
  {
    id: 'android.permission.CALL_PHONE',
    name: 'CALL_PHONE',
    category: 'telephony',
    protectionLevel: 'dangerous',
    runtime: true,
    minSdk: 1,
    maxSdk: null,
    usesFeature: 'android.hardware.telephony',
    description: 'Allows initiating a phone call without going through the dialer.'
  },
  {
    id: 'android.permission.FOREGROUND_SERVICE',
    name: 'FOREGROUND_SERVICE',
    category: 'system',
    protectionLevel: 'normal',
    runtime: false,
    minSdk: 28,
    maxSdk: null,
    description: 'Allows a regular application to use foreground services.'
  }
];

const PERMISSION_MAP = new Map(SUPPORTED_PERMISSIONS.map((p) => [p.id, p]));
const PERMISSION_SHORT_MAP = new Map(SUPPORTED_PERMISSIONS.map((p) => [p.name, p]));

// ============================================================================
// Validation & Utility Helpers
// ============================================================================

const JAVA_RESERVED_WORDS = new Set([
  'abstract', 'assert', 'boolean', 'break', 'byte', 'case', 'catch', 'char', 'class',
  'const', 'continue', 'default', 'do', 'double', 'else', 'enum', 'extends', 'final',
  'finally', 'float', 'for', 'goto', 'if', 'implements', 'import', 'instanceof', 'int',
  'interface', 'long', 'native', 'new', 'package', 'private', 'protected', 'public',
  'return', 'short', 'static', 'strictfp', 'super', 'switch', 'synchronized', 'this',
  'throw', 'throws', 'transient', 'try', 'void', 'volatile', 'while', 'true', 'false', 'null'
]);

function validatePackageName(pkg) {
  if (typeof pkg !== 'string' || pkg.length < 3 || pkg.length > 150) {
    return 'Package name must be a valid reverse-domain string (e.g., com.example.myapp).';
  }
  const segments = pkg.split('.');
  if (segments.length < 2) {
    return 'Package name must contain at least two dot-separated segments (e.g., com.example.app).';
  }
  for (const seg of segments) {
    if (!/^[a-zA-Z][a-zA-Z0-9_]*$/.test(seg)) {
      return `Invalid package segment "${seg}". Segments must start with a letter and contain only letters, digits, or underscores.`;
    }
    if (JAVA_RESERVED_WORDS.has(seg.toLowerCase())) {
      return `Invalid package segment "${seg}": Java reserved keyword is not allowed.`;
    }
  }
  return null;
}

function validateHexColor(color, fallback) {
  if (typeof color !== 'string' || !color.trim()) return fallback;
  const trimmed = color.trim();
  if (/^#[0-9a-fA-F]{6}$/.test(trimmed) || /^#[0-9a-fA-F]{8}$/.test(trimmed)) {
    return trimmed.toUpperCase();
  }
  return null;
}

function parseBoolean(val, defaultVal) {
  if (typeof val === 'boolean') return val;
  if (typeof val === 'string') {
    const lower = val.trim().toLowerCase();
    if (lower === 'true' || lower === '1' || lower === 'yes') return true;
    if (lower === 'false' || lower === '0' || lower === 'no') return false;
  }
  return defaultVal;
}

function parseJsonField(val, fallback) {
  if (val === undefined || val === null || val === '') return fallback;
  if (typeof val === 'object') return val;
  if (typeof val === 'string') {
    try {
      return JSON.parse(val);
    } catch {
      return null;
    }
  }
  return null;
}

function escapeXml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, "\\'");
}

function escapeJavaString(str) {
  return String(str)
    .replace(/\\/g, '\\\\')
    .replace(/"/g, '\\"')
    .replace(/\r/g, '\\r')
    .replace(/\n/g, '\\n');
}

function escapeGroovyString(str) {
  return String(str)
    .replace(/\\/g, '\\\\')
    .replace(/'/g, "\\'")
    .replace(/\$/g, '\\$');
}

function sanitizeFilename(name) {
  return String(name || 'app')
    .replace(/[^a-zA-Z0-9._-]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .toLowerCase() || 'app';
}

function getEncryptionKeyBuffer() {
  const raw = process.env.ASSET_ENCRYPTION_KEY;
  if (!raw || typeof raw !== 'string' || !raw.trim()) {
    const err = new Error('ASSET_ENCRYPTION_KEY environment variable is not configured.');
    err.statusCode = 500;
    err.code = 'MISSING_ENCRYPTION_KEY';
    throw err;
  }
  const buf = Buffer.from(raw.trim(), 'base64');
  if (buf.length !== 32) {
    const err = new Error('ASSET_ENCRYPTION_KEY must decode to exactly 32 bytes (AES-256).');
    err.statusCode = 500;
    err.code = 'INVALID_ENCRYPTION_KEY';
    throw err;
  }
  return buf;
}

function getAiConfig() {
  const apiKey = (process.env.AI_API_KEY || '').trim();
  const model = (process.env.AI_MODEL || '').trim();
  const provider = (process.env.AI_PROVIDER || '').trim().toLowerCase();

  const missing = [];
  if (!apiKey) missing.push('AI_API_KEY');
  if (!model) missing.push('AI_MODEL');
  if (!provider) missing.push('AI_PROVIDER');

  if (missing.length > 0) {
    const err = new Error(
      `Mandatory AI API key detection cannot run. Missing environment variable(s): ${missing.join(', ')}.`
    );
    err.statusCode = 500;
    err.code = 'MISSING_AI_CONFIG';
    throw err;
  }
  return { apiKey, model, provider };
}

function maskSecret(secret) {
  if (!secret || typeof secret !== 'string') return '****';
  const s = secret.trim();
  if (s.length <= 8) return '*'.repeat(Math.max(4, s.length));
  if (s.length <= 14) return `${s.slice(0, 2)}${'*'.repeat(s.length - 4)}${s.slice(-2)}`;
  return `${s.slice(0, 4)}...${'*'.repeat(8)}...${s.slice(-4)}`;
}

// ============================================================================
// Android SDK & Build Toolchain Discovery
// ============================================================================

async function discoverToolchain() {
  const androidHome =
    process.env.ANDROID_HOME ||
    process.env.ANDROID_SDK_ROOT ||
    '/opt/android-sdk';

  const info = {
    androidHome,
    androidSdkExists: fs.existsSync(androidHome),
    buildToolsVersion: null,
    buildToolsDir: null,
    compileSdk: 34,
    apksignerPath: null,
    zipalignPath: null,
    gradlePath: process.env.GRADLE_BIN || 'gradle',
    keytoolPath: process.env.KEYTOOL_BIN || 'keytool'
  };

  if (info.androidSdkExists) {
    const btRoot = path.join(androidHome, 'build-tools');
    if (fs.existsSync(btRoot)) {
      const versions = fs
        .readdirSync(btRoot, { withFileTypes: true })
        .filter((d) => d.isDirectory())
        .map((d) => d.name)
        .sort((a, b) => a.localeCompare(b, undefined, { numeric: true }));
      if (versions.length > 0) {
        info.buildToolsVersion = versions[versions.length - 1];
        info.buildToolsDir = path.join(btRoot, info.buildToolsVersion);
        const apksigner = path.join(info.buildToolsDir, 'apksigner');
        const zipalign = path.join(info.buildToolsDir, 'zipalign');
        if (fs.existsSync(apksigner)) info.apksignerPath = apksigner;
        if (fs.existsSync(zipalign)) info.zipalignPath = zipalign;
      }
    }

    const platformsRoot = path.join(androidHome, 'platforms');
    if (fs.existsSync(platformsRoot)) {
      const apis = fs
        .readdirSync(platformsRoot, { withFileTypes: true })
        .filter((d) => d.isDirectory() && /^android-\d+$/.test(d.name))
        .map((d) => parseInt(d.name.replace('android-', ''), 10))
        .sort((a, b) => a - b);
      if (apis.length > 0) {
        info.compileSdk = apis.includes(34) ? 34 : apis[apis.length - 1];
      }
    }
  }

  return info;
}

async function checkCommandAvailable(cmd, args = ['--version']) {
  try {
    const { stdout, stderr } = await execFileAsync(cmd, args, { timeout: 10000 });
    return { available: true, output: (stdout || stderr || '').trim().split('\n')[0] };
  } catch (err) {
    return { available: false, error: err.message };
  }
}

// ============================================================================
// Pure-JS Minimal PNG Generator & Image Format Detector
// ============================================================================

const CRC_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) {
      c = (c & 1) ? (0xedb88320 ^ (c >>> 1)) : (c >>> 1);
    }
    table[n] = c >>> 0;
  }
  return table;
})();

function crc32(buf) {
  let c = 0xffffffff;
  for (let i = 0; i < buf.length; i++) {
    c = CRC_TABLE[(c ^ buf[i]) & 0xff] ^ (c >>> 8);
  }
  return (c ^ 0xffffffff) >>> 0;
}

function pngChunk(type, data) {
  const lenBuf = Buffer.alloc(4);
  lenBuf.writeUInt32BE(data.length, 0);
  const typeBuf = Buffer.from(type, 'ascii');
  const crcBuf = Buffer.alloc(4);
  crcBuf.writeUInt32BE(crc32(Buffer.concat([typeBuf, data])), 0);
  return Buffer.concat([lenBuf, typeBuf, data, crcBuf]);
}

function generateSolidPng(size = 192, hexColor = '#2563EB') {
  const cleanHex = hexColor.replace('#', '');
  const r = parseInt(cleanHex.slice(0, 2), 16) || 37;
  const g = parseInt(cleanHex.slice(2, 4), 16) || 99;
  const b = parseInt(cleanHex.slice(4, 6), 16) || 235;

  const signature = Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]);
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(size, 0);
  ihdr.writeUInt32BE(size, 4);
  ihdr[8] = 8; // bit depth
  ihdr[9] = 6; // RGBA
  ihdr[10] = 0;
  ihdr[11] = 0;
  ihdr[12] = 0;

  const rowStride = 1 + size * 4;
  const raw = Buffer.alloc(rowStride * size);
  const center = size / 2;
  const radius = size * 0.42;

  for (let y = 0; y < size; y++) {
    const rowStart = y * rowStride;
    raw[rowStart] = 0; // filter none
    for (let x = 0; x < size; x++) {
      const px = rowStart + 1 + x * 4;
      const dx = x - center;
      const dy = y - center;
      const dist = Math.sqrt(dx * dx + dy * dy);

      if (dist <= radius * 0.35) {
        // Inner white emblem dot
        raw[px] = 255;
        raw[px + 1] = 255;
        raw[px + 2] = 255;
        raw[px + 3] = 255;
      } else if (dist <= radius) {
        raw[px] = r;
        raw[px + 1] = g;
        raw[px + 2] = b;
        raw[px + 3] = 255;
      } else {
        raw[px] = r;
        raw[px + 1] = g;
        raw[px + 2] = b;
        raw[px + 3] = 230;
      }
    }
  }

  const compressed = zlib.deflateSync(raw);
  return Buffer.concat([
    signature,
    pngChunk('IHDR', ihdr),
    pngChunk('IDAT', compressed),
    pngChunk('IEND', Buffer.alloc(0))
  ]);
}

function detectImageExtension(buffer) {
  if (!Buffer.isBuffer(buffer) || buffer.length < 12) return null;
  if (buffer[0] === 0x89 && buffer[1] === 0x50 && buffer[2] === 0x4e && buffer[3] === 0x47) {
    return 'png';
  }
  if (buffer[0] === 0xff && buffer[1] === 0xd8 && buffer[2] === 0xff) {
    return 'jpg';
  }
  if (
    buffer.slice(0, 4).toString('ascii') === 'RIFF' &&
    buffer.slice(8, 12).toString('ascii') === 'WEBP'
  ) {
    return 'webp';
  }
  return null;
}

// ============================================================================
// Mandatory API Key & Credential Detection (Local + AI Classification)
// ============================================================================

const SCANNABLE_EXTENSIONS = new Set([
  '.html', '.htm', '.css', '.js', '.mjs', '.cjs', '.ts', '.jsx', '.tsx',
  '.json', '.env', '.xml', '.yaml', '.yml', '.txt', '.config', '.properties', '.ini', '.svg'
]);

const LOCAL_SECRET_RULES = [
  {
    id: 'openai_key',
    provider: 'OpenAI',
    severity: 'critical',
    regex: /\b(sk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{20,})\b/g,
    description: 'Potential OpenAI API key detected.'
  },
  {
    id: 'anthropic_key',
    provider: 'Anthropic',
    severity: 'critical',
    regex: /\b(sk-ant-api\d{2}-[A-Za-z0-9_-]{20,})\b/g,
    description: 'Potential Anthropic API key detected.'
  },
  {
    id: 'google_api_key',
    provider: 'Google / Firebase',
    severity: 'high',
    regex: /\b(AIza[0-9A-Za-z_-]{35})\b/g,
    description: 'Google / Firebase API key detected.'
  },
  {
    id: 'stripe_secret_key',
    provider: 'Stripe',
    severity: 'critical',
    regex: /\b([rs]k_(?:live|test)_[0-9a-zA-Z]{16,})\b/g,
    description: 'Stripe secret/restricted API key detected.'
  },
  {
    id: 'stripe_publishable_key',
    provider: 'Stripe',
    severity: 'info',
    regex: /\b(pk_(?:live|test)_[0-9a-zA-Z]{16,})\b/g,
    description: 'Stripe publishable key detected.'
  },
  {
    id: 'aws_access_key',
    provider: 'AWS',
    severity: 'critical',
    regex: /\b((?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16})\b/g,
    description: 'AWS Access Key ID detected.'
  },
  {
    id: 'github_token',
    provider: 'GitHub',
    severity: 'critical',
    regex: /\b((?:gh[pousr]_[A-Za-z0-9_]{30,}|github_pat_[A-Za-z0-9_]{22,}))\b/g,
    description: 'GitHub personal access or OAuth token detected.'
  },
  {
    id: 'slack_token',
    provider: 'Slack',
    severity: 'critical',
    regex: /\b(xox[baprs]-[0-9A-Za-z-]{10,})\b/g,
    description: 'Slack token detected.'
  },
  {
    id: 'sendgrid_key',
    provider: 'SendGrid',
    severity: 'critical',
    regex: /\b(SG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,})\b/g,
    description: 'SendGrid API key detected.'
  },
  {
    id: 'twilio_key',
    provider: 'Twilio',
    severity: 'high',
    regex: /\b(SK[0-9a-fA-F]{32})\b/g,
    description: 'Twilio API key SID detected.'
  },
  {
    id: 'private_key_pem',
    provider: 'Cryptographic Key',
    severity: 'critical',
    regex: /(-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----)/g,
    description: 'Embedded private key header detected.'
  },
  {
    id: 'jwt_token',
    provider: 'JWT / OAuth / Supabase',
    severity: 'medium',
    regex: /\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b/g,
    description: 'Hardcoded JWT / Bearer token detected.'
  },
  {
    id: 'generic_credential',
    provider: 'Generic Credential',
    severity: 'high',
    regex: /(?:api[_-]?key|api[_-]?secret|access[_-]?token|auth[_-]?token|secret[_-]?key|client[_-]?secret|private[_-]?key|password|passwd|bearer)\s*[:=]\s*["'`]([^"'`\r\n]{6,120})["'`]/gi,
    description: 'Potential hardcoded credential assignment detected.'
  },
  {
    id: 'missing_or_placeholder_credential',
    provider: 'Configuration Issue',
    severity: 'warning',
    regex: /(?:api[_-]?key|api[_-]?secret|access[_-]?token|auth[_-]?token|client[_-]?secret|firebase[_-]?key)\s*[:=]\s*["'`](?:|YOUR_[A-Z0-9_]+|REPLACE_[A-Z0-9_]+|TODO[A-Z0-9_]*|INSERT_[A-Z0-9_]+|xxx+|example|<[^>]+>)["'`]/gi,
    description: 'Empty or placeholder API credential detected.'
  }
];

function sanitizeLineForAi(lineText, secretsInLine) {
  let sanitized = lineText;
  for (const raw of secretsInLine) {
    if (raw && raw.length > 0) {
      sanitized = sanitized.split(raw).join(maskSecret(raw));
    }
  }
  // Also mask any long quoted literal values in credential-looking assignments
  sanitized = sanitized.replace(
    /((?:key|token|secret|password|auth|bearer)\s*[:=]\s*["'`])([^"'`\r\n]{5,})(["'`])/gi,
    (_, p1, val, p3) => `${p1}${maskSecret(val)}${p3}`
  );
  return sanitized.slice(0, 220);
}

async function collectFilesRecursive(dir, baseDir = dir) {
  const entries = await fsp.readdir(dir, { withFileTypes: true });
  const files = [];
  for (const entry of entries) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      files.push(...(await collectFilesRecursive(full, baseDir)));
    } else if (entry.isFile()) {
      files.push({ fullPath: full, relativePath: path.relative(baseDir, full).replace(/\\/g, '/') });
    }
  }
  return files;
}

async function runLocalPatternScan(webRootDir) {
  const allFiles = await collectFilesRecursive(webRootDir);
  const localFindings = [];
  const metadataHints = [];
  let scannedFileCount = 0;

  for (const file of allFiles) {
    const ext = path.extname(file.relativePath).toLowerCase();
    const baseName = path.basename(file.relativePath).toLowerCase();
    const isEnvFile = baseName === '.env' || baseName.startsWith('.env.');
    if (!SCANNABLE_EXTENSIONS.has(ext) && !isEnvFile) continue;

    const stat = await fsp.stat(file.fullPath);
    if (stat.size > 2 * 1024 * 1024) continue; // skip >2MB single text files

    const content = await fsp.readFile(file.fullPath, 'utf8');
    scannedFileCount++;

    // Detect external SDK / API domain references safely (domains only)
    const providerHints = [];
    if (/api\.openai\.com/i.test(content)) providerHints.push('openai-endpoint');
    if (/firebase(app|io)?\.com|initializeApp/i.test(content)) providerHints.push('firebase-sdk');
    if (/js\.stripe\.com|api\.stripe\.com/i.test(content)) providerHints.push('stripe-sdk');
    if (/googleapis\.com|generativelanguage/i.test(content)) providerHints.push('google-apis');
    if (/api\.anthropic\.com/i.test(content)) providerHints.push('anthropic-endpoint');
    if (providerHints.length > 0) {
      metadataHints.push({ file: file.relativePath, hints: providerHints });
    }

    const lines = content.split(/\r?\n/);
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (!line || line.length > 4000) continue;

      for (const rule of LOCAL_SECRET_RULES) {
        rule.regex.lastIndex = 0;
        let match;
        while ((match = rule.regex.exec(line)) !== null) {
          const captured = match[1] !== undefined ? match[1] : match[0];
          const masked = captured.length > 0 ? maskSecret(captured) : '(empty)';
          const safeSnippet = sanitizeLineForAi(line, [captured]);

          localFindings.push({
            ruleId: rule.id,
            provider: rule.provider,
            severity: rule.severity,
            file: file.relativePath,
            line: i + 1,
            maskedValue: masked,
            safeSnippet,
            description: rule.description
          });
        }
      }
    }
  }

  // Deduplicate identical findings on same file/line/maskedValue
  const deduped = [];
  const seen = new Set();
  for (const f of localFindings) {
    const key = `${f.file}:${f.line}:${f.maskedValue}:${f.ruleId}`;
    if (!seen.has(key)) {
      seen.add(key);
      deduped.push(f);
    }
  }

  return {
    totalFiles: allFiles.length,
    scannedFileCount,
    localFindings: deduped,
    metadataHints: metadataHints.slice(0, 30)
  };
}

async function callAiClassification(scanPayload) {
  const { apiKey, model, provider } = getAiConfig();

  const systemPrompt = [
    'You are a mobile application security analyst reviewing masked static-analysis findings from a web-to-APK build.',
    'You NEVER receive raw secret values; only masked previews, file paths, line numbers, and safe metadata.',
    'Analyze the findings and respond ONLY with valid JSON matching this schema:',
    '{',
    '  "summary": "short overall assessment",',
    '  "riskLevel": "none|low|medium|high|critical",',
    '  "classifiedFindings": [',
    '    {',
    '      "file": "string",',
    '      "line": number,',
    '      "provider": "string",',
    '      "credentialType": "string",',
    '      "classification": "confirmed_secret|public_client_key|missing_or_malformed|false_positive",',
    '      "severity": "info|low|medium|high|critical",',
    '      "recommendation": "string"',
    '    }',
    '  ],',
    '  "recommendations": ["string"]',
    '}'
  ].join('\n');

  const safeInput = {
    scannedFileCount: scanPayload.scannedFileCount,
    metadataHints: scanPayload.metadataHints,
    findingsCount: scanPayload.localFindings.length,
    findings: scanPayload.localFindings.slice(0, 50).map((f) => ({
      ruleId: f.ruleId,
      provider: f.provider,
      severity: f.severity,
      file: f.file,
      line: f.line,
      maskedValue: f.maskedValue,
      safeSnippet: f.safeSnippet
    }))
  };

  const userPrompt = `Classify these masked scan findings and metadata:\n${JSON.stringify(safeInput)}`;

  let rawText = '';
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 30000);

  try {
    if (provider === 'openai' || provider === 'openrouter' || provider === 'groq' || provider === 'openai-compatible') {
      const defaultUrls = {
        openai: 'https://api.openai.com/v1/chat/completions',
        openrouter: 'https://openrouter.ai/api/v1/chat/completions',
        groq: 'https://api.groq.com/openai/v1/chat/completions'
      };
      const endpoint = (process.env.AI_BASE_URL || '').trim() || defaultUrls[provider];
      if (!endpoint) {
        const err = new Error('AI_BASE_URL is required when AI_PROVIDER is openai-compatible.');
        err.statusCode = 500;
        err.code = 'INVALID_AI_CONFIG';
        throw err;
      }

      const resp = await fetch(endpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${apiKey}`
        },
        body: JSON.stringify({
          model,
          temperature: 0.1,
          response_format: { type: 'json_object' },
          messages: [
            { role: 'system', content: systemPrompt },
            { role: 'user', content: userPrompt }
          ]
        }),
        signal: controller.signal
      });

      const body = await resp.json().catch(() => ({}));
      if (!resp.ok) {
        throw new Error(`AI provider (${provider}) returned HTTP ${resp.status}: ${body?.error?.message || resp.statusText}`);
      }
      rawText = body?.choices?.[0]?.message?.content || '';
    } else if (provider === 'anthropic') {
      const endpoint = (process.env.AI_BASE_URL || '').trim() || 'https://api.anthropic.com/v1/messages';
      const resp = await fetch(endpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-api-key': apiKey,
          'anthropic-version': '2023-06-01'
        },
        body: JSON.stringify({
          model,
          max_tokens: 1200,
          temperature: 0.1,
          system: systemPrompt,
          messages: [{ role: 'user', content: userPrompt }]
        }),
        signal: controller.signal
      });

      const body = await resp.json().catch(() => ({}));
      if (!resp.ok) {
        throw new Error(`AI provider (anthropic) returned HTTP ${resp.status}: ${body?.error?.message || resp.statusText}`);
      }
      rawText = body?.content?.[0]?.text || '';
    } else if (provider === 'gemini' || provider === 'google') {
      const endpoint =
        (process.env.AI_BASE_URL || '').trim() ||
        `https://generativelanguage.googleapis.com/v1beta/models/${encodeURIComponent(model)}:generateContent?key=${encodeURIComponent(apiKey)}`;

      const resp = await fetch(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          contents: [{ parts: [{ text: `${systemPrompt}\n\n${userPrompt}` }] }],
          generationConfig: {
            temperature: 0.1,
            responseMimeType: 'application/json'
          }
        }),
        signal: controller.signal
      });

      const body = await resp.json().catch(() => ({}));
      if (!resp.ok) {
        throw new Error(`AI provider (${provider}) returned HTTP ${resp.status}: ${body?.error?.message || resp.statusText}`);
      }
      rawText = body?.candidates?.[0]?.content?.parts?.[0]?.text || '';
    } else {
      const err = new Error(`Unsupported AI_PROVIDER "${provider}". Supported: openai, anthropic, gemini, google, openrouter, groq, openai-compatible.`);
      err.statusCode = 500;
      err.code = 'UNSUPPORTED_AI_PROVIDER';
      throw err;
    }
  } catch (err) {
    if (err.statusCode) throw err;
    const wrapped = new Error(`Mandatory AI API key detection service failed: ${err.message}`);
    wrapped.statusCode = 502;
    wrapped.code = 'AI_SERVICE_ERROR';
    throw wrapped;
  } finally {
    clearTimeout(timer);
  }

  // Parse JSON from AI response
  let parsedAi = null;
  try {
    const cleaned = rawText.replace(/^```json\s*/i, '').replace(/^```\s*/i, '').replace(/```\s*$/i, '').trim();
    parsedAi = JSON.parse(cleaned);
  } catch {
    const wrapped = new Error('AI API key detection returned malformed non-JSON output.');
    wrapped.statusCode = 502;
    wrapped.code = 'AI_INVALID_RESPONSE';
    throw wrapped;
  }

  return {
    provider,
    model,
    rawClassification: parsedAi
  };
}

async function performMandatoryApiKeyScan(webRootDir) {
  // Verify AI config up-front so mandatory scan never gets skipped
  getAiConfig();

  const localResult = await runLocalPatternScan(webRootDir);
  const aiResult = await callAiClassification(localResult);

  return {
    scannedAt: new Date().toISOString(),
    totalFiles: localResult.totalFiles,
    scannedTextFiles: localResult.scannedFileCount,
    detectedCount: localResult.localFindings.length,
    localFindings: localResult.localFindings.map((f) => ({
      ruleId: f.ruleId,
      provider: f.provider,
      severity: f.severity,
      file: f.file,
      line: f.line,
      maskedValue: f.maskedValue,
      description: f.description
    })),
    metadataHints: localResult.metadataHints,
    aiAnalysis: {
      provider: aiResult.provider,
      model: aiResult.model,
      summary: aiResult.rawClassification?.summary || 'Scan completed.',
      riskLevel: aiResult.rawClassification?.riskLevel || (localResult.localFindings.length > 0 ? 'medium' : 'none'),
      classifiedFindings: Array.isArray(aiResult.rawClassification?.classifiedFindings)
        ? aiResult.rawClassification.classifiedFindings
        : [],
      recommendations: Array.isArray(aiResult.rawClassification?.recommendations)
        ? aiResult.rawClassification.recommendations
        : []
    },
    credentialsModified: false,
    securityDisclaimer:
      'API keys or credentials embedded in client-side web applications can be extracted from compiled APKs. Detected credentials were NOT modified or deleted so application behavior is preserved; rotate and move sensitive keys to a backend service.'
  };
}

// ============================================================================
// ZIP Extraction, Path-Traversal Safety & HTML Entry Detection
// ============================================================================

async function extractAndValidateWebsiteZip(zipPath, extractDir) {
  let zip;
  try {
    zip = new AdmZip(zipPath);
  } catch (err) {
    const e = new Error(`Invalid or corrupted ZIP file: ${err.message}`);
    e.statusCode = 400;
    e.code = 'INVALID_ZIP';
    throw e;
  }

  const entries = zip.getEntries();
  if (!entries || entries.length === 0) {
    const e = new Error('Uploaded ZIP file is empty.');
    e.statusCode = 400;
    e.code = 'EMPTY_ZIP';
    throw e;
  }

  if (entries.length > MAX_EXTRACTED_FILES) {
    const e = new Error(`ZIP contains too many files (${entries.length} > ${MAX_EXTRACTED_FILES}).`);
    e.statusCode = 400;
    e.code = 'ZIP_TOO_MANY_FILES';
    throw e;
  }

  await fsp.mkdir(extractDir, { recursive: true });
  const resolvedBase = path.resolve(extractDir) + path.sep;
  let totalUncompressed = 0;

  for (const entry of entries) {
    const entryName = entry.entryName.replace(/\\/g, '/');
    if (entryName.startsWith('__MACOSX/') || entryName === '__MACOSX') continue;

    if (path.isAbsolute(entryName) || entryName.split('/').includes('..')) {
      const e = new Error(`Unsafe path detected in ZIP entry: ${entryName}`);
      e.statusCode = 400;
      e.code = 'UNSAFE_ZIP_PATH';
      throw e;
    }

    const targetPath = path.resolve(extractDir, entryName);
    if (!targetPath.startsWith(resolvedBase) && targetPath !== path.resolve(extractDir)) {
      const e = new Error(`Zip Slip traversal detected in entry: ${entryName}`);
      e.statusCode = 400;
      e.code = 'UNSAFE_ZIP_PATH';
      throw e;
    }

    if (entry.isDirectory) {
      await fsp.mkdir(targetPath, { recursive: true });
    } else {
      const data = entry.getData();
      totalUncompressed += data.length;
      if (totalUncompressed > MAX_EXTRACTED_SIZE_BYTES) {
        const e = new Error(`Extracted website exceeds maximum uncompressed size (${Math.round(MAX_EXTRACTED_SIZE_BYTES / (1024 * 1024))} MB).`);
        e.statusCode = 400;
        e.code = 'ZIP_SIZE_LIMIT';
        throw e;
      }
      await fsp.mkdir(path.dirname(targetPath), { recursive: true });
      await fsp.writeFile(targetPath, data);
    }
  }

  // Locate web root & entry HTML
  let webRootDir = extractDir;
  let entryHtml = 'index.html';

  if (!fs.existsSync(path.join(webRootDir, 'index.html'))) {
    const topEntries = (await fsp.readdir(extractDir, { withFileTypes: true }))
      .filter((d) => d.name !== '__MACOSX');

    if (topEntries.length === 1 && topEntries[0].isDirectory()) {
      const nestedDir = path.join(extractDir, topEntries[0].name);
      if (fs.existsSync(path.join(nestedDir, 'index.html'))) {
        webRootDir = nestedDir;
      } else {
        const nestedHtml = (await fsp.readdir(nestedDir)).find((f) => /\.html?$/i.test(f));
        if (nestedHtml) {
          webRootDir = nestedDir;
          entryHtml = nestedHtml;
        }
      }
    }
  }

  if (!fs.existsSync(path.join(webRootDir, entryHtml))) {
    const allFiles = await collectFilesRecursive(webRootDir);
    const anyHtml = allFiles.find((f) => /\.html?$/i.test(f.relativePath));
    if (!anyHtml) {
      const e = new Error('Missing HTML files: uploaded ZIP must contain index.html or at least one HTML file.');
      e.statusCode = 400;
      e.code = 'MISSING_HTML_FILES';
      throw e;
    }
    entryHtml = anyHtml.relativePath;
  }

  return { webRootDir, entryHtml };
}

// ============================================================================
// AES-256-GCM Asset Encryption
// ============================================================================

async function encryptWebAssets(webRootDir, outputAssetsDir, keyBuffer) {
  const files = await collectFilesRecursive(webRootDir);
  await fsp.mkdir(outputAssetsDir, { recursive: true });

  let encryptedCount = 0;
  let totalPlaintextBytes = 0;
  let totalEncryptedBytes = 0;

  for (const file of files) {
    const plaintext = await fsp.readFile(file.fullPath);
    totalPlaintextBytes += plaintext.length;

    const nonce = crypto.randomBytes(12); // unique 96-bit GCM nonce per asset
    const cipher = crypto.createCipheriv('aes-256-gcm', keyBuffer, nonce);
    const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const authTag = cipher.getAuthTag(); // 16 bytes

    // Binary layout: [12-byte nonce][ciphertext][16-byte GCM auth tag]
    const packaged = Buffer.concat([nonce, ciphertext, authTag]);
    const destPath = path.join(outputAssetsDir, `${file.relativePath}.enc`);
    await fsp.mkdir(path.dirname(destPath), { recursive: true });
    await fsp.writeFile(destPath, packaged);

    encryptedCount++;
    totalEncryptedBytes += packaged.length;
  }

  return {
    encryptedCount,
    totalPlaintextBytes,
    totalEncryptedBytes,
    algorithm: 'AES-256-GCM'
  };
}

// ============================================================================
// Keystore Generator
// ============================================================================

async function generateKeystoreFile({
  alias = 'app-release-key',
  storeType = 'PKCS12',
  validityDays = 10000,
  keySize = 2048,
  dname = {}
}) {
  const cleanType = String(storeType || 'PKCS12').toUpperCase();
  if (cleanType !== 'PKCS12' && cleanType !== 'JKS') {
    const err = new Error('Invalid keystoreType. Must be PKCS12 or JKS.');
    err.statusCode = 400;
    err.code = 'INVALID_KEYSTORE_TYPE';
    throw err;
  }

  const cleanAlias = String(alias || 'app-release-key').replace(/[^a-zA-Z0-9._-]/g, '').slice(0, 64);
  if (!cleanAlias) {
    const err = new Error('Keystore alias must contain valid alphanumeric characters.');
    err.statusCode = 400;
    err.code = 'INVALID_ALIAS';
    throw err;
  }

  const days = Math.min(Math.max(parseInt(validityDays, 10) || 10000, 365), 36500);
  const bits = parseInt(keySize, 10) === 4096 ? 4096 : 2048;

  const keystoreId = crypto.randomUUID();
  const ext = cleanType === 'PKCS12' ? 'p12' : 'jks';
  const filename = `keystore-${cleanAlias}-${keystoreId.slice(0, 8)}.${ext}`;
  const filePath = path.join(KEYSTORES_DIR, filename);

  // Cryptographically secure random passwords (never logged!)
  const storePassword = crypto.randomBytes(24).toString('base64url');
  // PKCS12 standard expects identical storepass and keypass in modern JDK keytool
  const keyPassword = cleanType === 'PKCS12' ? storePassword : crypto.randomBytes(24).toString('base64url');

  const safeDnameVal = (v, def) => String(v || def).replace(/[,="\\]/g, ' ').trim() || def;
  const cn = safeDnameVal(dname.cn, 'Android App Developer');
  const ou = safeDnameVal(dname.ou, 'Mobile Engineering');
  const o = safeDnameVal(dname.o, 'Organization');
  const l = safeDnameVal(dname.l, 'City');
  const st = safeDnameVal(dname.st, 'State');
  const c = safeDnameVal(dname.c, 'US').slice(0, 2).toUpperCase();
  const dnameString = `CN=${cn}, OU=${ou}, O=${o}, L=${l}, ST=${st}, C=${c}`;

  const toolchain = await discoverToolchain();
  const args = [
    '-genkeypair',
    '-v',
    '-storetype', cleanType,
    '-keystore', filePath,
    '-alias', cleanAlias,
    '-keyalg', 'RSA',
    '-keysize', String(bits),
    '-validity', String(days),
    '-storepass', storePassword,
    '-keypass', keyPassword,
    '-dname', dnameString
  ];

  try {
    await execFileAsync(toolchain.keytoolPath, args, { timeout: 30000 });
  } catch (err) {
    const e = new Error(`Keystore generation failed: ${err.message}`);
    e.statusCode = 500;
    e.code = 'KEYSTORE_GENERATION_FAILED';
    throw e;
  }

  const record = {
    keystoreId,
    filename,
    filePath,
    storeType: cleanType,
    alias: cleanAlias,
    storePassword,
    keyPassword,
    validityDays: days,
    keySize: bits,
    createdAt: Date.now(),
    downloaded: false,
    activeReads: 0
  };
  keystores.set(keystoreId, record);

  return record;
}

// ============================================================================
// Android Project Programmatic Template Generator
// ============================================================================

function formatJavaByteArray(buf) {
  const bytes = [];
  for (let i = 0; i < buf.length; i++) {
    // Convert unsigned byte 0..255 to signed Java byte -128..127
    const signed = buf[i] > 127 ? buf[i] - 256 : buf[i];
    bytes.push(`(byte) ${signed}`);
  }
  return `{ ${bytes.join(', ')} }`;
}

function buildManifestXml(config, resolvedPermissions) {
  const permissionLines = [];
  const featureSet = new Set();

  for (const perm of resolvedPermissions) {
    if (perm.maxSdk !== null && perm.maxSdk !== undefined) {
      permissionLines.push(
        `    <uses-permission android:name="${perm.id}" android:maxSdkVersion="${perm.maxSdk}" />`
      );
    } else {
      permissionLines.push(`    <uses-permission android:name="${perm.id}" />`);
    }
    if (perm.usesFeature) {
      featureSet.add(perm.usesFeature);
    }
  }

  const featureLines = Array.from(featureSet).map(
    (feat) => `    <uses-feature android:name="${feat}" android:required="false" />`
  );

  const orientationMap = {
    unspecified: 'unspecified',
    portrait: 'portrait',
    landscape: 'landscape',
    sensor: 'sensor',
    fullSensor: 'fullSensor'
  };
  const androidOrientation = orientationMap[config.orientation] || 'unspecified';
  const cleartext = config.webviewConfig.mixedContentMode === 'always' || config.webviewConfig.allowCleartextTraffic;

  return `<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android">

${permissionLines.join('\n')}
${featureLines.join('\n')}

    <application
        android:allowBackup="false"
        android:hardwareAccelerated="${config.webviewConfig.hardwareAccelerated ? 'true' : 'false'}"
        android:icon="@mipmap/ic_launcher"
        android:roundIcon="@mipmap/ic_launcher_round"
        android:label="@string/app_name"
        android:supportsRtl="true"
        android:theme="@style/AppTheme"
        android:usesCleartextTraffic="${cleartext ? 'true' : 'false'}">

        <activity
            android:name=".MainActivity"
            android:configChanges="orientation|screenSize|keyboardHidden|smallestScreenSize|screenLayout"
            android:exported="true"
            android:screenOrientation="${androidOrientation}">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
    </application>
</manifest>
`;
}

function buildAssetCipherJava(packageName, keyBuffer) {
  // Split key with a per-build random 32-byte XOR mask so the raw base64 secret isn't stored verbatim
  const mask = crypto.randomBytes(32);
  const masked = Buffer.alloc(32);
  for (let i = 0; i < 32; i++) {
    masked[i] = keyBuffer[i] ^ mask[i];
  }

  return `package ${packageName};

import android.content.res.AssetManager;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public final class AssetCipher {
    private static final String ASSET_PREFIX = "enc_www/";
    private static final String ASSET_SUFFIX = ".enc";
    private static final int NONCE_LEN = 12;
    private static final int GCM_TAG_BITS = 128;

    private static final byte[] PART_A = new byte[] ${formatJavaByteArray(masked)};
    private static final byte[] PART_B = new byte[] ${formatJavaByteArray(mask)};

    private AssetCipher() {}

    public static byte[] decryptAsset(AssetManager assets, String relativePath) throws Exception {
        String assetName = ASSET_PREFIX + relativePath + ASSET_SUFFIX;
        byte[] encrypted = readAllBytesCompat(assets, assetName);
        if (encrypted.length <= NONCE_LEN + 16) {
            throw new IOException("Corrupted encrypted asset: " + relativePath);
        }

        byte[] nonce = new byte[NONCE_LEN];
        System.arraycopy(encrypted, 0, nonce, 0, NONCE_LEN);

        byte[] key = new byte[32];
        for (int i = 0; i < 32; i++) {
            key[i] = (byte) (PART_A[i] ^ PART_B[i]);
        }

        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
            GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_BITS, nonce);
            cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmSpec);
            return cipher.doFinal(encrypted, NONCE_LEN, encrypted.length - NONCE_LEN);
        } finally {
            Arrays.fill(key, (byte) 0);
        }
    }

    private static byte[] readAllBytesCompat(AssetManager assets, String path) throws IOException {
        try (InputStream is = assets.open(path);
             ByteArrayOutputStream buffer = new ByteArrayOutputStream()) {
            byte[] chunk = new byte[8192];
            int nRead;
            while ((nRead = is.read(chunk, 0, chunk.length)) != -1) {
                buffer.write(chunk, 0, nRead);
            }
            return buffer.toByteArray();
        }
    }
}
`;
}

function buildMainActivityJava(config, resolvedPermissions) {
  const pkg = config.packageName;
  const sb = config.statusBar;
  const nb = config.navigationBar;
  const wv = config.webviewConfig;

  const permChecks = [];
  for (const perm of resolvedPermissions) {
    if (!perm.runtime) continue;
    if (perm.minSdk > 23 && perm.maxSdk) {
      permChecks.push(
        `        if (Build.VERSION.SDK_INT >= ${perm.minSdk} && Build.VERSION.SDK_INT <= ${perm.maxSdk}) candidates.add("${perm.id}");`
      );
    } else if (perm.minSdk > 23) {
      permChecks.push(
        `        if (Build.VERSION.SDK_INT >= ${perm.minSdk}) candidates.add("${perm.id}");`
      );
    } else if (perm.maxSdk) {
      permChecks.push(
        `        if (Build.VERSION.SDK_INT <= ${perm.maxSdk}) candidates.add("${perm.id}");`
      );
    } else {
      permChecks.push(`        candidates.add("${perm.id}");`);
    }
  }

  const cacheModeMap = {
    default: 'WebSettings.LOAD_DEFAULT',
    noCache: 'WebSettings.LOAD_NO_CACHE',
    cacheElseNetwork: 'WebSettings.LOAD_CACHE_ELSE_NETWORK',
    cacheOnly: 'WebSettings.LOAD_CACHE_ONLY'
  };
  const javaCacheMode = cacheModeMap[wv.cacheMode] || 'WebSettings.LOAD_DEFAULT';

  const mixedContentMap = {
    never: 'WebSettings.MIXED_CONTENT_NEVER_ALLOW',
    compatibility: 'WebSettings.MIXED_CONTENT_COMPATIBILITY_MODE',
    always: 'WebSettings.MIXED_CONTENT_ALWAYS_ALLOW'
  };
  const javaMixedContent = mixedContentMap[wv.mixedContentMode] || 'WebSettings.MIXED_CONTENT_NEVER_ALLOW';

  return `package ${pkg};

import android.Manifest;
import android.annotation.SuppressLint;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.graphics.Color;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.view.Gravity;
import android.view.View;
import android.view.Window;
import android.view.WindowManager;
import android.webkit.GeolocationPermissions;
import android.webkit.PermissionRequest;
import android.webkit.ValueCallback;
import android.webkit.WebChromeClient;
import android.webkit.WebResourceRequest;
import android.webkit.WebResourceResponse;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.FrameLayout;
import android.widget.ImageView;
import androidx.activity.OnBackPressedCallback;
import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;
import androidx.annotation.NonNull;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.content.ContextCompat;
import androidx.core.view.WindowCompat;
import androidx.core.view.WindowInsetsCompat;
import androidx.core.view.WindowInsetsControllerCompat;
import java.io.ByteArrayInputStream;
import java.net.URLDecoder;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

public class MainActivity extends AppCompatActivity {
    private static final String VIRTUAL_HOST = "appassets.local";
    private static final String VIRTUAL_ORIGIN = "https://" + VIRTUAL_HOST;
    private static final String ENTRY_HTML = "${escapeJavaString(config.entryHtml)}";
    private static final boolean INTERNET_ACCESS = ${config.internetAccess ? 'true' : 'false'};
    private static final String SPLASH_BG = "${escapeJavaString(config.splashBackground)}";
    private static final boolean STATUS_BAR_HIDDEN = ${sb.hidden ? 'true' : 'false'};
    private static final String STATUS_BAR_COLOR = "${escapeJavaString(sb.color)}";
    private static final boolean STATUS_BAR_LIGHT_ICONS = ${sb.lightIcons ? 'true' : 'false'};
    private static final boolean NAV_BAR_HIDDEN = ${nb.hidden ? 'true' : 'false'};
    private static final String NAV_BAR_COLOR = "${escapeJavaString(nb.color)}";
    private static final boolean NAV_BAR_LIGHT_ICONS = ${nb.lightIcons ? 'true' : 'false'};

    private WebView webView;
    private FrameLayout splashOverlay;
    private boolean splashDismissed = false;
    private ValueCallback<Uri[]> filePathCallback;

    private final ActivityResultLauncher<String[]> permissionLauncher =
        registerForActivityResult(new ActivityResultContracts.RequestMultiplePermissions(), result -> {});

    private final ActivityResultLauncher<Intent> fileChooserLauncher =
        registerForActivityResult(new ActivityResultContracts.StartActivityForResult(), result -> {
            if (filePathCallback == null) return;
            Uri[] results = WebChromeClient.FileChooserParams.parseResult(result.getResultCode(), result.getData());
            filePathCallback.onReceiveValue(results);
            filePathCallback = null;
        });

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        configureSystemBars();

        FrameLayout root = new FrameLayout(this);
        root.setLayoutParams(new FrameLayout.LayoutParams(
            FrameLayout.LayoutParams.MATCH_PARENT,
            FrameLayout.LayoutParams.MATCH_PARENT
        ));

        webView = new WebView(this);
        webView.setLayoutParams(new FrameLayout.LayoutParams(
            FrameLayout.LayoutParams.MATCH_PARENT,
            FrameLayout.LayoutParams.MATCH_PARENT
        ));
        root.addView(webView);

        splashOverlay = new FrameLayout(this);
        splashOverlay.setLayoutParams(new FrameLayout.LayoutParams(
            FrameLayout.LayoutParams.MATCH_PARENT,
            FrameLayout.LayoutParams.MATCH_PARENT
        ));
        splashOverlay.setBackgroundColor(Color.parseColor(SPLASH_BG));
        ImageView splashIcon = new ImageView(this);
        int iconSizePx = (int) (144 * getResources().getDisplayMetrics().density);
        FrameLayout.LayoutParams iconParams = new FrameLayout.LayoutParams(iconSizePx, iconSizePx, Gravity.CENTER);
        splashIcon.setLayoutParams(iconParams);
        splashIcon.setScaleType(ImageView.ScaleType.FIT_CENTER);
        splashIcon.setImageResource(R.drawable.splash_logo);
        splashOverlay.addView(splashIcon);
        root.addView(splashOverlay);

        setContentView(root);
        configureWebView();
        requestConfiguredRuntimePermissions();

        getOnBackPressedDispatcher().addCallback(this, new OnBackPressedCallback(true) {
            @Override
            public void handleOnBackPressed() {
                if (webView != null && webView.canGoBack()) {
                    webView.goBack();
                } else {
                    finish();
                }
            }
        });

        webView.loadUrl(VIRTUAL_ORIGIN + "/" + ENTRY_HTML);

        // Failsafe splash timeout
        new Handler(Looper.getMainLooper()).postDelayed(this::dismissSplash, 3500);
    }

    private void dismissSplash() {
        if (splashDismissed || splashOverlay == null) return;
        splashDismissed = true;
        splashOverlay.animate().alpha(0f).setDuration(250).withEndAction(() -> {
            if (splashOverlay != null) {
                splashOverlay.setVisibility(View.GONE);
            }
        }).start();
    }

    private void configureSystemBars() {
        Window window = getWindow();
        window.addFlags(WindowManager.LayoutParams.FLAG_DRAWS_SYSTEM_BAR_BACKGROUNDS);
        window.setStatusBarColor(Color.parseColor(STATUS_BAR_COLOR));
        window.setNavigationBarColor(Color.parseColor(NAV_BAR_COLOR));

        boolean anyHidden = STATUS_BAR_HIDDEN || NAV_BAR_HIDDEN;
        WindowCompat.setDecorFitsSystemWindows(window, !anyHidden);

        WindowInsetsControllerCompat controller = WindowCompat.getInsetsController(window, window.getDecorView());
        if (controller != null) {
            controller.setAppearanceLightStatusBars(!STATUS_BAR_LIGHT_ICONS);
            controller.setAppearanceLightNavigationBars(!NAV_BAR_LIGHT_ICONS);
            controller.setSystemBarsBehavior(WindowInsetsControllerCompat.BEHAVIOR_SHOW_TRANSIENT_BARS_BY_SWIPE);
            if (STATUS_BAR_HIDDEN) {
                controller.hide(WindowInsetsCompat.Type.statusBars());
            }
            if (NAV_BAR_HIDDEN) {
                controller.hide(WindowInsetsCompat.Type.navigationBars());
            }
        }
    }

    @SuppressLint("SetJavaScriptEnabled")
    private void configureWebView() {
        WebSettings settings = webView.getSettings();
        settings.setJavaScriptEnabled(${wv.javascriptEnabled ? 'true' : 'false'});
        settings.setDomStorageEnabled(${wv.domStorageEnabled ? 'true' : 'false'});
        settings.setDatabaseEnabled(${wv.domStorageEnabled ? 'true' : 'false'});
        settings.setAllowFileAccess(${wv.allowFileAccess ? 'true' : 'false'});
        settings.setSupportZoom(${wv.zoomEnabled ? 'true' : 'false'});
        settings.setBuiltInZoomControls(${wv.zoomEnabled ? 'true' : 'false'});
        settings.setDisplayZoomControls(false);
        settings.setLoadWithOverviewMode(true);
        settings.setUseWideViewPort(true);
        settings.setCacheMode(${javaCacheMode});
        settings.setMixedContentMode(${javaMixedContent});
        settings.setMediaPlaybackRequiresUserGesture(${wv.mediaPlaybackRequiresUserGesture ? 'true' : 'false'});
        settings.setGeolocationEnabled(${wv.geolocationEnabled ? 'true' : 'false'});
        ${wv.userAgent ? `settings.setUserAgentString("${escapeJavaString(wv.userAgent)}");` : ''}

        webView.setWebViewClient(new WebViewClient() {
            @Override
            public WebResourceResponse shouldInterceptRequest(WebView view, WebResourceRequest request) {
                Uri url = request.getUrl();
                if (url == null) return super.shouldInterceptRequest(view, request);

                String host = url.getHost();
                if (!VIRTUAL_HOST.equalsIgnoreCase(host)) {
                    if (!INTERNET_ACCESS) {
                        Map<String, String> headers = new HashMap<>();
                        return new WebResourceResponse("text/plain", "UTF-8", 403, "Forbidden", headers,
                            new ByteArrayInputStream("Internet access disabled".getBytes()));
                    }
                    return null;
                }

                String relPath = normalizePath(url.getEncodedPath());
                if (relPath == null) {
                    return errorResponse(403, "Forbidden");
                }

                byte[] decrypted = tryDecrypt(relPath);
                String resolvedPath = relPath;
                if (decrypted == null && !relPath.contains(".")) {
                    String candidate = relPath.isEmpty() ? ENTRY_HTML : relPath + "/index.html";
                    decrypted = tryDecrypt(candidate);
                    if (decrypted != null) resolvedPath = candidate;
                }

                if (decrypted == null) {
                    return errorResponse(404, "Not Found");
                }

                String mime = getMimeType(resolvedPath);
                String charset = isTextMime(mime) ? "UTF-8" : null;
                Map<String, String> headers = new HashMap<>();
                headers.put("Access-Control-Allow-Origin", "*");
                headers.put("Cache-Control", "no-store");
                return new WebResourceResponse(mime, charset, 200, "OK", headers, new ByteArrayInputStream(decrypted));
            }

            @Override
            public boolean shouldOverrideUrlLoading(WebView view, WebResourceRequest request) {
                Uri uri = request.getUrl();
                if (uri == null) return false;
                String scheme = uri.getScheme() != null ? uri.getScheme().toLowerCase(Locale.ROOT) : "";
                if (VIRTUAL_HOST.equalsIgnoreCase(uri.getHost())) {
                    return false;
                }
                if (("http".equals(scheme) || "https".equals(scheme)) && INTERNET_ACCESS) {
                    return false;
                }
                if ("tel".equals(scheme) || "mailto".equals(scheme) || "sms".equals(scheme)) {
                    try {
                        startActivity(new Intent(Intent.ACTION_VIEW, uri));
                    } catch (Exception ignored) {}
                    return true;
                }
                return !INTERNET_ACCESS;
            }

            @Override
            public void onPageFinished(WebView view, String url) {
                super.onPageFinished(view, url);
                dismissSplash();
            }
        });

        webView.setWebChromeClient(new WebChromeClient() {
            @Override
            public void onGeolocationPermissionsShowPrompt(String origin, GeolocationPermissions.Callback callback) {
                boolean granted = ContextCompat.checkSelfPermission(MainActivity.this, Manifest.permission.ACCESS_FINE_LOCATION) == PackageManager.PERMISSION_GRANTED
                    || ContextCompat.checkSelfPermission(MainActivity.this, Manifest.permission.ACCESS_COARSE_LOCATION) == PackageManager.PERMISSION_GRANTED;
                callback.invoke(origin, granted, false);
            }

            @Override
            public void onPermissionRequest(final PermissionRequest request) {
                List<String> grantedResources = new ArrayList<>();
                for (String res : request.getResources()) {
                    if (PermissionRequest.RESOURCE_VIDEO_CAPTURE.equals(res) &&
                        ContextCompat.checkSelfPermission(MainActivity.this, Manifest.permission.CAMERA) == PackageManager.PERMISSION_GRANTED) {
                        grantedResources.add(res);
                    } else if (PermissionRequest.RESOURCE_AUDIO_CAPTURE.equals(res) &&
                        ContextCompat.checkSelfPermission(MainActivity.this, Manifest.permission.RECORD_AUDIO) == PackageManager.PERMISSION_GRANTED) {
                        grantedResources.add(res);
                    }
                }
                if (!grantedResources.isEmpty()) {
                    request.grant(grantedResources.toArray(new String[0]));
                } else {
                    request.deny();
                }
            }

            @Override
            public boolean onShowFileChooser(WebView webView, ValueCallback<Uri[]> callback, FileChooserParams params) {
                if (filePathCallback != null) {
                    filePathCallback.onReceiveValue(null);
                }
                filePathCallback = callback;
                try {
                    fileChooserLauncher.launch(params.createIntent());
                    return true;
                } catch (Exception e) {
                    filePathCallback = null;
                    return false;
                }
            }
        });
    }

    private void requestConfiguredRuntimePermissions() {
        List<String> candidates = new ArrayList<>();
${permChecks.join('\n')}
        List<String> missing = new ArrayList<>();
        for (String p : candidates) {
            if (ContextCompat.checkSelfPermission(this, p) != PackageManager.PERMISSION_GRANTED) {
                missing.add(p);
            }
        }
        if (!missing.isEmpty()) {
            permissionLauncher.launch(missing.toArray(new String[0]));
        }
    }

    private byte[] tryDecrypt(String relPath) {
        if (relPath == null || relPath.isEmpty()) return null;
        try {
            return AssetCipher.decryptAsset(getAssets(), relPath);
        } catch (Exception e) {
            return null;
        }
    }

    private String normalizePath(String encodedPath) {
        if (encodedPath == null || encodedPath.isEmpty() || "/".equals(encodedPath)) {
            return ENTRY_HTML;
        }
        try {
            String decoded = URLDecoder.decode(encodedPath, "UTF-8");
            while (decoded.startsWith("/")) {
                decoded = decoded.substring(1);
            }
            if (decoded.isEmpty()) return ENTRY_HTML;
            if (decoded.contains("..") || decoded.contains("\\\\")) return null;
            return decoded;
        } catch (Exception e) {
            return null;
        }
    }

    private WebResourceResponse errorResponse(int code, String msg) {
        Map<String, String> headers = new HashMap<>();
        return new WebResourceResponse("text/plain", "UTF-8", code, msg, headers,
            new ByteArrayInputStream(msg.getBytes()));
    }

    private String getMimeType(String path) {
        String lower = path.toLowerCase(Locale.ROOT);
        if (lower.endsWith(".html") || lower.endsWith(".htm")) return "text/html";
        if (lower.endsWith(".css")) return "text/css";
        if (lower.endsWith(".js") || lower.endsWith(".mjs")) return "application/javascript";
        if (lower.endsWith(".json")) return "application/json";
        if (lower.endsWith(".svg")) return "image/svg+xml";
        if (lower.endsWith(".png")) return "image/png";
        if (lower.endsWith(".jpg") || lower.endsWith(".jpeg")) return "image/jpeg";
        if (lower.endsWith(".webp")) return "image/webp";
        if (lower.endsWith(".gif")) return "image/gif";
        if (lower.endsWith(".ico")) return "image/x-icon";
        if (lower.endsWith(".woff2")) return "font/woff2";
        if (lower.endsWith(".woff")) return "font/woff";
        if (lower.endsWith(".ttf")) return "font/ttf";
        if (lower.endsWith(".otf")) return "font/otf";
        if (lower.endsWith(".xml")) return "application/xml";
        if (lower.endsWith(".mp3")) return "audio/mpeg";
        if (lower.endsWith(".mp4")) return "video/mp4";
        if (lower.endsWith(".webm")) return "video/webm";
        if (lower.endsWith(".wasm")) return "application/wasm";
        if (lower.endsWith(".txt")) return "text/plain";
        return "application/octet-stream";
    }

    private boolean isTextMime(String mime) {
        return mime.startsWith("text/") ||
            "application/javascript".equals(mime) ||
            "application/json".equals(mime) ||
            "application/xml".equals(mime) ||
            "image/svg+xml".equals(mime);
    }

    @Override
    protected void onDestroy() {
        if (webView != null) {
            webView.destroy();
        }
        super.onDestroy();
    }
}
`;
}

async function generateAndroidProject({
  projectDir,
  webRootDir,
  config,
  resolvedPermissions,
  encryptionKeyBuffer,
  appLogoBuffer,
  splashLogoBuffer,
  compileSdk
}) {
  const appDir = path.join(projectDir, 'app');
  const mainDir = path.join(appDir, 'src', 'main');
  const pkgPath = config.packageName.split('.').join(path.sep);
  const javaDir = path.join(mainDir, 'java', pkgPath);
  const resDir = path.join(mainDir, 'res');
  const encAssetsDir = path.join(mainDir, 'assets', 'enc_www');

  await fsp.mkdir(javaDir, { recursive: true });
  await fsp.mkdir(path.join(resDir, 'values'), { recursive: true });
  await fsp.mkdir(path.join(resDir, 'drawable'), { recursive: true });
  await fsp.mkdir(path.join(resDir, 'mipmap-xxhdpi'), { recursive: true });
  await fsp.mkdir(path.join(resDir, 'mipmap-xxxhdpi'), { recursive: true });

  // 1. Encrypt web assets directly into app/src/main/assets/enc_www (no plaintext copies!)
  const encryptionStats = await encryptWebAssets(webRootDir, encAssetsDir, encryptionKeyBuffer);

  // 2. Write Launcher & Splash Logo assets with exact format extensions
  const fallbackPng = generateSolidPng(192, config.splashBackground);
  const appLogoBuf = appLogoBuffer || fallbackPng;
  const appLogoExt = detectImageExtension(appLogoBuf) || 'png';
  const finalAppLogo = detectImageExtension(appLogoBuf) ? appLogoBuf : fallbackPng;

  const splashLogoBuf = splashLogoBuffer || finalAppLogo;
  const splashLogoExt = detectImageExtension(splashLogoBuf) || 'png';
  const finalSplashLogo = detectImageExtension(splashLogoBuf) ? splashLogoBuf : finalAppLogo;

  for (const density of ['mipmap-xxhdpi', 'mipmap-xxxhdpi']) {
    await fsp.writeFile(path.join(resDir, density, `ic_launcher.${appLogoExt}`), finalAppLogo);
    await fsp.writeFile(path.join(resDir, density, `ic_launcher_round.${appLogoExt}`), finalAppLogo);
  }
  await fsp.writeFile(path.join(resDir, 'drawable', `splash_logo.${splashLogoExt}`), finalSplashLogo);

  // 3. Gradle root configuration
  await fsp.writeFile(
    path.join(projectDir, 'gradle.properties'),
    [
      `org.gradle.jvmargs=-Xmx${GRADLE_MAX_HEAP} -Dfile.encoding=UTF-8`,
      'android.useAndroidX=true',
      'android.enableJetifier=false',
      'android.nonTransitiveRClass=true'
    ].join('\n') + '\n'
  );

  await fsp.writeFile(
    path.join(projectDir, 'settings.gradle'),
    `pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}
dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
    }
}
rootProject.name = "WebViewApk"
include ':app'
`
  );

  await fsp.writeFile(
    path.join(projectDir, 'build.gradle'),
    `plugins {
    id 'com.android.application' version '8.2.2' apply false
}
`
  );

  await fsp.writeFile(
    path.join(appDir, 'build.gradle'),
    `plugins {
    id 'com.android.application'
}

android {
    namespace '${escapeGroovyString(config.packageName)}'
    compileSdk ${compileSdk}

    defaultConfig {
        applicationId '${escapeGroovyString(config.packageName)}'
        minSdk 24
        targetSdk ${compileSdk}
        versionCode ${config.versionCode}
        versionName '${escapeGroovyString(config.versionName)}'
    }

    buildTypes {
        release {
            minifyEnabled false
            shrinkResources false
            signingConfig null
        }
    }

    compileOptions {
        sourceCompatibility JavaVersion.VERSION_17
        targetCompatibility JavaVersion.VERSION_17
    }
}

dependencies {
    implementation 'androidx.appcompat:appcompat:1.6.1'
}
`
  );

  // 4. Android resources (strings.xml & styles.xml)
  await fsp.writeFile(
    path.join(resDir, 'values', 'strings.xml'),
    `<?xml version="1.0" encoding="utf-8"?>
<resources>
    <string name="app_name">${escapeXml(config.appName)}</string>
</resources>
`
  );

  await fsp.writeFile(
    path.join(resDir, 'values', 'styles.xml'),
    `<?xml version="1.0" encoding="utf-8"?>
<resources>
    <style name="AppTheme" parent="Theme.AppCompat.Light.NoActionBar">
        <item name="android:windowBackground">@drawable/splash_window_bg</item>
    </style>
</resources>
`
  );

  await fsp.writeFile(
    path.join(resDir, 'drawable', 'splash_window_bg.xml'),
    `<?xml version="1.0" encoding="utf-8"?>
<layer-list xmlns:android="http://schemas.android.com/apk/res/android">
    <item>
        <color android:color="${config.splashBackground}" />
    </item>
    <item android:gravity="center">
        <bitmap
            android:gravity="center"
            android:src="@drawable/splash_logo" />
    </item>
</layer-list>
`
  );

  // 5. AndroidManifest.xml & Java Sources
  await fsp.writeFile(
    path.join(mainDir, 'AndroidManifest.xml'),
    buildManifestXml(config, resolvedPermissions)
  );
  await fsp.writeFile(
    path.join(javaDir, 'AssetCipher.java'),
    buildAssetCipherJava(config.packageName, encryptionKeyBuffer)
  );
  await fsp.writeFile(
    path.join(javaDir, 'MainActivity.java'),
    buildMainActivityJava(config, resolvedPermissions)
  );

  return encryptionStats;
}

// ============================================================================
// Process Execution with Timeout & Signing Helpers
// ============================================================================

function runCommandWithTimeout(command, args, cwd, timeoutMs) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      cwd,
      env: process.env,
      stdio: ['ignore', 'pipe', 'pipe']
    });
    activeChildProcesses.add(child);

    let stdout = '';
    let stderr = '';
    let timedOut = false;

    const timer = setTimeout(() => {
      timedOut = true;
      child.kill('SIGTERM');
      setTimeout(() => {
        if (!child.killed) child.kill('SIGKILL');
      }, 5000);
    }, timeoutMs);

    child.stdout.on('data', (chunk) => {
      stdout += chunk.toString();
      if (stdout.length > 64000) stdout = stdout.slice(-64000);
    });
    child.stderr.on('data', (chunk) => {
      stderr += chunk.toString();
      if (stderr.length > 64000) stderr = stderr.slice(-64000);
    });

    child.on('error', (err) => {
      clearTimeout(timer);
      activeChildProcesses.delete(child);
      reject(err);
    });

    child.on('close', (code) => {
      clearTimeout(timer);
      activeChildProcesses.delete(child);
      if (timedOut) {
        const err = new Error(`Build command timed out after ${Math.round(timeoutMs / 1000)}s.`);
        err.code = 'BUILD_TIMEOUT';
        err.statusCode = 504;
        return reject(err);
      }
      if (code !== 0) {
        const tail = (stderr || stdout).trim().split('\n').slice(-25).join('\n');
        const err = new Error(`Command "${path.basename(command)}" exited with code ${code}:\n${tail}`);
        err.code = 'GRADLE_BUILD_FAILED';
        err.statusCode = 500;
        return reject(err);
      }
      resolve({ stdout, stderr });
    });
  });
}

async function resolveSigningConfig(reqBody, uploadedKeystoreFile, buildTempDir) {
  // 1. Pre-generated keystoreId from Keystore Generator API
  if (reqBody.keystoreId) {
    const ks = keystores.get(String(reqBody.keystoreId).trim());
    if (!ks || !fs.existsSync(ks.filePath)) {
      const err = new Error(`Keystore ID "${reqBody.keystoreId}" not found or expired.`);
      err.statusCode = 400;
      err.code = 'KEYSTORE_NOT_FOUND';
      throw err;
    }
    return {
      source: 'generated_keystore',
      keystorePath: ks.filePath,
      alias: ks.alias,
      storePassword: ks.storePassword,
      keyPassword: ks.keyPassword,
      keystoreRecord: ks
    };
  }

  // 2. Uploaded keystore file in multipart request
  if (uploadedKeystoreFile) {
    const alias = String(reqBody.keystoreAlias || '').trim();
    const storePassword = String(reqBody.keystorePassword || '');
    const keyPassword = String(reqBody.keyPassword || storePassword);
    if (!alias || !storePassword) {
      const err = new Error('Uploaded keystore requires keystoreAlias and keystorePassword.');
      err.statusCode = 400;
      err.code = 'INVALID_SIGNING_CONFIG';
      throw err;
    }
    return {
      source: 'uploaded_keystore',
      keystorePath: uploadedKeystoreFile.path,
      alias,
      storePassword,
      keyPassword
    };
  }

  // 3. Preconfigured Render environment keystore (file path or base64)
  const envPath = (process.env.SIGNING_KEYSTORE_PATH || '').trim();
  const envBase64 = (process.env.SIGNING_KEYSTORE_BASE64 || '').trim();
  const envAlias = (process.env.SIGNING_KEY_ALIAS || '').trim();
  const envStorePass = process.env.SIGNING_KEYSTORE_PASSWORD || '';
  const envKeyPass = process.env.SIGNING_KEY_PASSWORD || envStorePass;

  if ((envPath || envBase64) && envAlias && envStorePass) {
    let ksPath = envPath;
    if (!ksPath && envBase64) {
      ksPath = path.join(buildTempDir, 'env-signing-keystore.p12');
      await fsp.writeFile(ksPath, Buffer.from(envBase64, 'base64'));
    }
    if (!fs.existsSync(ksPath)) {
      const err = new Error('Configured SIGNING_KEYSTORE_PATH file does not exist on server.');
      err.statusCode = 500;
      err.code = 'MISSING_ENV_KEYSTORE';
      throw err;
    }
    return {
      source: 'environment_keystore',
      keystorePath: ksPath,
      alias: envAlias,
      storePassword: envStorePass,
      keyPassword: envKeyPass
    };
  }

  const err = new Error(
    'No APK signing keystore provided. Generate one via POST /api/keystore/generate and pass keystoreId, upload keystoreFile with credentials, or configure SIGNING_KEYSTORE_* environment variables.'
  );
  err.statusCode = 400;
  err.code = 'MISSING_SIGNING_KEYSTORE';
  throw err;
}

async function signAndVerifyApk({ unsignedApkPath, alignedApkPath, signedApkPath, signing, toolchain }) {
  if (!toolchain.zipalignPath || !toolchain.apksignerPath) {
    const err = new Error(
      `Android build-tools (zipalign/apksigner) not found under ${toolchain.androidHome}.`
    );
    err.statusCode = 500;
    err.code = 'MISSING_SIGNING_TOOLS';
    throw err;
  }

  try {
    await execFileAsync(toolchain.zipalignPath, ['-p', '-f', '4', unsignedApkPath, alignedApkPath], {
      timeout: 60000
    });
  } catch (err) {
    const e = new Error(`zipalign failed: ${err.message}`);
    e.statusCode = 500;
    e.code = 'APK_ZIPALIGN_FAILED';
    throw e;
  }

  try {
    await execFileAsync(
      toolchain.apksignerPath,
      [
        'sign',
        '--ks', signing.keystorePath,
        '--ks-key-alias', signing.alias,
        '--ks-pass', `pass:${signing.storePassword}`,
        '--key-pass', `pass:${signing.keyPassword}`,
        '--out', signedApkPath,
        alignedApkPath
      ],
      { timeout: 60000 }
    );
  } catch (err) {
    const e = new Error(`APK signing failed (check keystore alias/password): ${err.stderr || err.message}`);
    e.statusCode = 400;
    e.code = 'APK_SIGNING_FAILED';
    throw e;
  }

  try {
    const { stdout } = await execFileAsync(toolchain.apksignerPath, ['verify', '--verbose', signedApkPath], {
      timeout: 30000
    });
    return { verified: true, details: stdout.trim().split('\n').slice(0, 6).join(' | ') };
  } catch (err) {
    const e = new Error(`APK signature verification failed: ${err.stderr || err.message}`);
    e.statusCode = 500;
    e.code = 'APK_VERIFY_FAILED';
    throw e;
  }
}

// ============================================================================
// Build Configuration Parser & Permission Resolver
// ============================================================================

function parseAndValidateBuildConfig(body, entryHtml) {
  const appName = String(body.appName || '').trim();
  if (!appName || appName.length > 60) {
    return { error: 'appName is required and must be 1–60 characters.', code: 'INVALID_APP_NAME' };
  }

  const packageName = String(body.packageName || '').trim();
  const pkgErr = validatePackageName(packageName);
  if (pkgErr) {
    return { error: pkgErr, code: 'INVALID_PACKAGE_NAME' };
  }

  const versionName = String(body.versionName || '1.0.0').trim();
  if (!versionName || versionName.length > 32) {
    return { error: 'versionName must be 1–32 characters.', code: 'INVALID_VERSION_NAME' };
  }

  const versionCode = parseInt(body.versionCode || '1', 10);
  if (!Number.isInteger(versionCode) || versionCode < 1 || versionCode > 2100000000) {
    return { error: 'versionCode must be a positive integer.', code: 'INVALID_VERSION_CODE' };
  }

  const splashBackground = validateHexColor(body.splashBackground, '#FFFFFF');
  if (!splashBackground) {
    return { error: 'splashBackground must be a valid hex color (e.g., #FFFFFF).', code: 'INVALID_COLOR' };
  }

  const allowedOrientations = new Set(['unspecified', 'portrait', 'landscape', 'sensor', 'fullSensor']);
  const orientation = String(body.orientation || 'unspecified').trim();
  if (!allowedOrientations.has(orientation)) {
    return {
      error: `Invalid orientation "${orientation}". Allowed: ${Array.from(allowedOrientations).join(', ')}.`,
      code: 'INVALID_ORIENTATION'
    };
  }

  const internetAccess = parseBoolean(body.internetAccess, true);

  const rawStatusBar = parseJsonField(body.statusBar, {});
  if (rawStatusBar === null) {
    return { error: 'statusBar must be valid JSON.', code: 'INVALID_STATUS_BAR' };
  }
  const sbColor = validateHexColor(rawStatusBar.color, '#1E293B');
  if (!sbColor) {
    return { error: 'statusBar.color must be a valid hex color.', code: 'INVALID_COLOR' };
  }
  const statusBar = {
    hidden: parseBoolean(rawStatusBar.hidden, false),
    color: sbColor,
    lightIcons: parseBoolean(rawStatusBar.lightIcons, true)
  };

  const rawNavBar = parseJsonField(body.navigationBar, {});
  if (rawNavBar === null) {
    return { error: 'navigationBar must be valid JSON.', code: 'INVALID_NAV_BAR' };
  }
  const nbColor = validateHexColor(rawNavBar.color, '#0F172A');
  if (!nbColor) {
    return { error: 'navigationBar.color must be a valid hex color.', code: 'INVALID_COLOR' };
  }
  const navigationBar = {
    hidden: parseBoolean(rawNavBar.hidden, false),
    color: nbColor,
    lightIcons: parseBoolean(rawNavBar.lightIcons, true)
  };

  const rawWebView = parseJsonField(body.webviewConfig, {});
  if (rawWebView === null) {
    return { error: 'webviewConfig must be valid JSON.', code: 'INVALID_WEBVIEW_CONFIG' };
  }
  const webviewConfig = {
    javascriptEnabled: parseBoolean(rawWebView.javascriptEnabled, true),
    domStorageEnabled: parseBoolean(rawWebView.domStorageEnabled, true),
    allowFileAccess: parseBoolean(rawWebView.allowFileAccess, false),
    zoomEnabled: parseBoolean(rawWebView.zoomEnabled, false),
    cacheMode: ['default', 'noCache', 'cacheElseNetwork', 'cacheOnly'].includes(rawWebView.cacheMode)
      ? rawWebView.cacheMode
      : 'default',
    mixedContentMode: ['never', 'compatibility', 'always'].includes(rawWebView.mixedContentMode)
      ? rawWebView.mixedContentMode
      : 'never',
    allowCleartextTraffic: parseBoolean(rawWebView.allowCleartextTraffic, false),
    hardwareAccelerated: parseBoolean(rawWebView.hardwareAccelerated, true),
    mediaPlaybackRequiresUserGesture: parseBoolean(rawWebView.mediaPlaybackRequiresUserGesture, false),
    geolocationEnabled: parseBoolean(rawWebView.geolocationEnabled, true),
    userAgent: typeof rawWebView.userAgent === 'string' ? rawWebView.userAgent.trim().slice(0, 300) : ''
  };

  // Permissions resolution
  const selectAllPermissions = parseBoolean(body.selectAllPermissions, false);
  let requestedPermissions = [];
  if (body.permissions !== undefined && body.permissions !== '') {
    const parsedPerms = parseJsonField(body.permissions, null);
    if (Array.isArray(parsedPerms)) {
      requestedPermissions = parsedPerms;
    } else if (typeof body.permissions === 'string') {
      requestedPermissions = body.permissions.split(',').map((s) => s.trim()).filter(Boolean);
    } else {
      return { error: 'permissions must be a JSON array or comma-separated list.', code: 'INVALID_PERMISSIONS' };
    }
  }

  const resolvedMap = new Map();
  if (selectAllPermissions) {
    for (const perm of SUPPORTED_PERMISSIONS) {
      if (!internetAccess && perm.id === 'android.permission.INTERNET') continue;
      resolvedMap.set(perm.id, perm);
    }
  } else {
    const invalidPerms = [];
    for (const rawPerm of requestedPermissions) {
      const normalized = String(rawPerm || '').trim();
      const found = PERMISSION_MAP.get(normalized) || PERMISSION_SHORT_MAP.get(normalized.toUpperCase());
      if (!found) {
        invalidPerms.push(normalized);
      } else {
        resolvedMap.set(found.id, found);
      }
    }
    if (invalidPerms.length > 0) {
      return {
        error: `Unsupported or restricted Android permission(s): ${invalidPerms.join(', ')}. Query GET /api/config for supported permissions.`,
        code: 'INVALID_ANDROID_PERMISSIONS'
      };
    }
    if (internetAccess) {
      resolvedMap.set('android.permission.INTERNET', PERMISSION_MAP.get('android.permission.INTERNET'));
      resolvedMap.set('android.permission.ACCESS_NETWORK_STATE', PERMISSION_MAP.get('android.permission.ACCESS_NETWORK_STATE'));
    }
  }

  return {
    config: {
      appName,
      packageName,
      versionName,
      versionCode,
      entryHtml,
      splashBackground,
      orientation,
      internetAccess,
      statusBar,
      navigationBar,
      webviewConfig
    },
    resolvedPermissions: Array.from(resolvedMap.values())
  };
}

// ============================================================================
// Core Build Execution Pipeline
// ============================================================================

async function executeApkBuild(buildRecord, context) {
  const {
    buildDir,
    extractDir,
    webRootDir,
    projectDir,
    config,
    resolvedPermissions,
    encryptionKeyBuffer,
    appLogoBuffer,
    splashLogoBuffer,
    signing,
    uploadedFilesToClean
  } = context;

  buildRecord.isBuilding = true;
  if (signing.keystoreRecord) {
    signing.keystoreRecord.activeReads++;
  }

  try {
    buildRecord.stage = 'encrypting_and_generating_project';
    const toolchain = await discoverToolchain();

    const encryptionStats = await generateAndroidProject({
      projectDir,
      webRootDir,
      config,
      resolvedPermissions,
      encryptionKeyBuffer,
      appLogoBuffer,
      splashLogoBuffer,
      compileSdk: toolchain.compileSdk
    });
    buildRecord.encryption = encryptionStats;

    // Delete extracted plaintext ZIP contents immediately before Gradle packaging
    await fsp.rm(extractDir, { recursive: true, force: true });
    for (const f of uploadedFilesToClean) {
      await fsp.rm(f, { force: true }).catch(() => {});
    }

    buildRecord.stage = 'compiling_gradle_apk';
    const gradleArgs = ['assembleRelease', '--no-watch-fs'];
    if (GRADLE_NO_DAEMON) gradleArgs.push('--no-daemon');

    await runCommandWithTimeout(toolchain.gradlePath, gradleArgs, projectDir, BUILD_TIMEOUT_MS);

    const releaseDir = path.join(projectDir, 'app', 'build', 'outputs', 'apk', 'release');
    const candidateUnsigned = path.join(releaseDir, 'app-release-unsigned.apk');
    const candidateFallback = path.join(releaseDir, 'app-release.apk');
    const unsignedApkPath = fs.existsSync(candidateUnsigned) ? candidateUnsigned : candidateFallback;

    if (!fs.existsSync(unsignedApkPath)) {
      const err = new Error('Gradle build completed without producing a release APK.');
      err.code = 'MISSING_GRADLE_OUTPUT';
      err.statusCode = 500;
      throw err;
    }

    buildRecord.stage = 'signing_and_verifying_apk';
    const alignedApkPath = path.join(buildDir, 'aligned.apk');
    const apkFilename = `${sanitizeFilename(config.appName)}-v${sanitizeFilename(config.versionName)}.apk`;
    const finalApkPath = path.join(buildDir, apkFilename);

    const signatureInfo = await signAndVerifyApk({
      unsignedApkPath,
      alignedApkPath,
      signedApkPath: finalApkPath,
      signing,
      toolchain
    });

    // Clean up intermediate Gradle build files & aligned temp APK immediately
    await fsp.rm(alignedApkPath, { force: true }).catch(() => {});
    await fsp.rm(projectDir, { recursive: true, force: true }).catch(() => {});

    // Check 20 MB maximum APK size limit
    const stat = await fsp.stat(finalApkPath);
    if (stat.size > MAX_APK_SIZE_BYTES) {
      await fsp.rm(finalApkPath, { force: true }).catch(() => {});
      const sizeMb = (stat.size / (1024 * 1024)).toFixed(2);
      const err = new Error(
        `Built APK size (${sizeMb} MB) exceeds the strict 20 MB maximum limit.`
      );
      err.statusCode = 413;
      err.code = 'APK_SIZE_LIMIT_EXCEEDED';
      throw err;
    }

    buildRecord.status = 'completed';
    buildRecord.stage = 'ready';
    buildRecord.completedAt = new Date().toISOString();
    buildRecord.expiresAt = Date.now() + APK_EXPIRATION_MS;
    buildRecord.apkPath = finalApkPath;
    buildRecord.apkFilename = apkFilename;
    buildRecord.apkSizeBytes = stat.size;
    buildRecord.apkSizeMB = Number((stat.size / (1024 * 1024)).toFixed(3));
    buildRecord.signature = {
      verified: signatureInfo.verified,
      source: signing.source,
      alias: signing.alias,
      details: signatureInfo.details
    };
    buildRecord.securityLimitationNote = SECURITY_LIMITATION_NOTE;
  } catch (err) {
    buildRecord.status = 'failed';
    buildRecord.stage = 'failed';
    buildRecord.completedAt = new Date().toISOString();
    buildRecord.error = {
      code: err.code || 'BUILD_FAILED',
      message: err.message || 'APK build failed.'
    };
    // Clean up failed build directory immediately
    await fsp.rm(buildDir, { recursive: true, force: true }).catch(() => {});
    for (const f of uploadedFilesToClean) {
      await fsp.rm(f, { force: true }).catch(() => {});
    }
  } finally {
    buildRecord.isBuilding = false;
    if (signing.keystoreRecord) {
      signing.keystoreRecord.activeReads = Math.max(0, signing.keystoreRecord.activeReads - 1);
    }
  }
}

// ============================================================================
// Temporary Storage Cleanup Manager
// ============================================================================

async function runCleanupSweep({ forceExpired = true } = {}) {
  const now = Date.now();
  const report = {
    removedBuilds: 0,
    removedKeystores: 0,
    skippedActive: 0,
    skippedUndownloadedKeystores: 0
  };

  for (const [buildId, record] of builds.entries()) {
    if (record.isBuilding || record.activeDownloads > 0) {
      report.skippedActive++;
      continue;
    }

    const expired =
      record.status === 'completed' &&
      record.expiresAt &&
      (forceExpired ? now >= record.expiresAt : false);
    const oldFailed =
      record.status === 'failed' &&
      now - record.createdAtMs > APK_EXPIRATION_MS;

    if (expired || oldFailed) {
      if (record.buildDir) {
        await fsp.rm(record.buildDir, { recursive: true, force: true }).catch(() => {});
      }
      builds.delete(buildId);
      report.removedBuilds++;
    }
  }

  for (const [ksId, ks] of keystores.entries()) {
    if (ks.activeReads > 0) {
      report.skippedActive++;
      continue;
    }
    // Never delete a keystore before the user has downloaded it
    if (!ks.downloaded) {
      report.skippedUndownloadedKeystores++;
      continue;
    }
    if (now - ks.createdAt >= KEYSTORE_EXPIRATION_MS) {
      await fsp.rm(ks.filePath, { force: true }).catch(() => {});
      keystores.delete(ksId);
      report.removedKeystores++;
    }
  }

  // Sweep orphaned files in UPLOADS_DIR older than 15 minutes
  try {
    const uploadFiles = await fsp.readdir(UPLOADS_DIR);
    for (const file of uploadFiles) {
      const full = path.join(UPLOADS_DIR, file);
      const st = await fsp.stat(full).catch(() => null);
      if (st && now - st.mtimeMs > 15 * 60 * 1000) {
        await fsp.rm(full, { force: true }).catch(() => {});
      }
    }
  } catch {
    // ignore upload sweep error
  }

  return report;
}

const cleanupInterval = setInterval(() => {
  runCleanupSweep().catch((err) => {
    console.error('[Cleanup Error]', err.message);
  });
}, CLEANUP_INTERVAL_MS);
cleanupInterval.unref();

// ============================================================================
// Express Application & Multer Upload Setup
// ============================================================================

const app = express();
app.disable('x-powered-by');
app.use(express.json({ limit: '2mb' }));
app.use(express.urlencoded({ extended: true, limit: '2mb' }));

const uploadStorage = multer.diskStorage({
  destination: (_, __, cb) => cb(null, UPLOADS_DIR),
  filename: (_, file, cb) => {
    const safeExt = path.extname(file.originalname || '').replace(/[^a-zA-Z0-9.]/g, '').slice(0, 10);
    cb(null, `${Date.now()}-${crypto.randomUUID()}${safeExt}`);
  }
});

const upload = multer({
  storage: uploadStorage,
  limits: {
    fileSize: MAX_ZIP_UPLOAD_BYTES,
    files: 4
  }
});

// Reject new builds during graceful shutdown
app.use((req, res, next) => {
  if (isShuttingDown && req.method === 'POST') {
    return res.status(503).json({
      success: false,
      error: { code: 'SERVER_SHUTTING_DOWN', message: 'Server is shutting down and not accepting new jobs.' }
    });
  }
  next();
});

// ============================================================================
// REST API Routes (API-Only, No Frontend)
// ============================================================================

app.get('/', (req, res) => {
  res.json({
    service: 'HTML/CSS/JS to Android APK Build Server',
    mode: 'api-only',
    endpoints: {
      health: 'GET /health | GET /api/health',
      config: 'GET /api/config',
      scan: 'POST /api/scan',
      generateKeystore: 'POST /api/keystore/generate',
      downloadKeystore: 'GET /api/keystore/:keystoreId/download',
      buildApk: 'POST /api/build',
      buildStatus: 'GET /api/build/:buildId/status',
      downloadApk: 'GET /api/build/:buildId/download',
      cleanup: 'POST /api/cleanup'
    }
  });
});

async function handleHealth(req, res) {
  const toolchain = await discoverToolchain();
  const [gradleCheck, keytoolCheck] = await Promise.all([
    checkCommandAvailable(toolchain.gradlePath, ['--version']),
    checkCommandAvailable(toolchain.keytoolPath, ['-help'])
  ]);

  let encryptionKeyConfigured = false;
  try {
    getEncryptionKeyBuffer();
    encryptionKeyConfigured = true;
  } catch {
    encryptionKeyConfigured = false;
  }

  let aiScannerConfigured = false;
  try {
    getAiConfig();
    aiScannerConfigured = true;
  } catch {
    aiScannerConfigured = false;
  }

  const envSigningConfigured = Boolean(
    (process.env.SIGNING_KEYSTORE_PATH || process.env.SIGNING_KEYSTORE_BASE64) &&
      process.env.SIGNING_KEY_ALIAS &&
      process.env.SIGNING_KEYSTORE_PASSWORD
  );

  const healthy =
    toolchain.androidSdkExists &&
    Boolean(toolchain.apksignerPath) &&
    Boolean(toolchain.zipalignPath) &&
    gradleCheck.available &&
    encryptionKeyConfigured &&
    aiScannerConfigured;

  res.status(healthy ? 200 : 503).json({
    status: healthy ? 'ok' : 'degraded',
    timestamp: new Date().toISOString(),
    uptimeSeconds: Math.floor(process.uptime()),
    toolchain: {
      nodeVersion: process.version,
      androidSdkFound: toolchain.androidSdkExists,
      compileSdk: toolchain.compileSdk,
      buildToolsVersion: toolchain.buildToolsVersion,
      apksignerAvailable: Boolean(toolchain.apksignerPath),
      zipalignAvailable: Boolean(toolchain.zipalignPath),
      gradleAvailable: gradleCheck.available,
      keytoolAvailable: keytoolCheck.available
    },
    configuration: {
      assetEncryptionKeyConfigured: encryptionKeyConfigured,
      aiScannerConfigured,
      aiProvider: process.env.AI_PROVIDER || null,
      aiModel: process.env.AI_MODEL || null,
      environmentSigningKeystoreConfigured: envSigningConfigured
    },
    limits: {
      maxApkSizeBytes: MAX_APK_SIZE_BYTES,
      maxApkSizeMB: 20,
      maxZipUploadBytes: MAX_ZIP_UPLOAD_BYTES,
      buildTimeoutMs: BUILD_TIMEOUT_MS
    }
  });
}

app.get('/health', handleHealth);
app.get('/api/health', handleHealth);

app.get('/api/config', (req, res) => {
  res.json({
    success: true,
    limits: {
      maxApkSizeBytes: MAX_APK_SIZE_BYTES,
      maxApkSizeMB: 20,
      maxZipUploadBytes: MAX_ZIP_UPLOAD_BYTES,
      apkExpirationMinutes: Math.round(APK_EXPIRATION_MS / 60000)
    },
    buildParameters: {
      requiredFiles: ['websiteZip (ZIP containing HTML, CSS, JS, images, fonts)'],
      optionalFiles: ['appLogo (PNG/JPG/WEBP)', 'splashLogo (PNG/JPG/WEBP)', 'keystoreFile (PKCS12/JKS)'],
      requiredFields: ['appName', 'packageName'],
      optionalFields: {
        versionName: '1.0.0',
        versionCode: 1,
        splashBackground: '#FFFFFF',
        orientation: ['unspecified', 'portrait', 'landscape', 'sensor', 'fullSensor'],
        internetAccess: true,
        statusBar: { hidden: false, color: '#1E293B', lightIcons: true },
        navigationBar: { hidden: false, color: '#0F172A', lightIcons: true },
        webviewConfig: {
          javascriptEnabled: true,
          domStorageEnabled: true,
          allowFileAccess: false,
          zoomEnabled: false,
          cacheMode: ['default', 'noCache', 'cacheElseNetwork', 'cacheOnly'],
          mixedContentMode: ['never', 'compatibility', 'always'],
          allowCleartextTraffic: false,
          hardwareAccelerated: true,
          mediaPlaybackRequiresUserGesture: false,
          geolocationEnabled: true,
          userAgent: ''
        },
        selectAllPermissions: false,
        permissions: 'Array of supported permission IDs or short names',
        keystoreId: 'ID from POST /api/keystore/generate'
      }
    },
    supportedPermissions: SUPPORTED_PERMISSIONS
  });
});

// Standalone Mandatory AI API Key Detection Endpoint
app.post('/api/scan', upload.single('websiteZip'), async (req, res, next) => {
  const uploadedZip = req.file;
  if (!uploadedZip) {
    return res.status(400).json({
      success: false,
      error: { code: 'MISSING_ZIP', message: 'websiteZip file is required.' }
    });
  }

  const scanDir = path.join(WORK_ROOT, `scan-${crypto.randomUUID()}`);
  try {
    const { webRootDir } = await extractAndValidateWebsiteZip(uploadedZip.path, scanDir);
    const report = await performMandatoryApiKeyScan(webRootDir);
    res.json({ success: true, report });
  } catch (err) {
    next(err);
  } finally {
    await fsp.rm(uploadedZip.path, { force: true }).catch(() => {});
    await fsp.rm(scanDir, { recursive: true, force: true }).catch(() => {});
  }
});

// Keystore Generator Endpoint
app.post('/api/keystore/generate', async (req, res, next) => {
  try {
    const record = await generateKeystoreFile({
      alias: req.body?.alias,
      storeType: req.body?.keystoreType || req.body?.storeType || 'PKCS12',
      validityDays: req.body?.validityDays,
      keySize: req.body?.keySize,
      dname: req.body?.dname || {}
    });

    const directDownload =
      req.query.direct === 'true' ||
      req.headers.accept === 'application/octet-stream';

    if (directDownload) {
      record.activeReads++;
      res.setHeader('Content-Type', 'application/octet-stream');
      res.setHeader('Content-Disposition', `attachment; filename="${record.filename}"`);
      res.setHeader('X-Keystore-Id', record.keystoreId);
      res.setHeader('X-Keystore-Alias', record.alias);
      res.setHeader('X-Keystore-Type', record.storeType);
      res.setHeader('X-Keystore-Warning', KEYSTORE_LOSS_WARNING);

      const stream = fs.createReadStream(record.filePath);
      stream.on('close', () => {
        record.downloaded = true;
        record.activeReads = Math.max(0, record.activeReads - 1);
      });
      stream.on('error', (err) => {
        record.activeReads = Math.max(0, record.activeReads - 1);
        next(err);
      });
      return stream.pipe(res);
    }

    res.status(201).json({
      success: true,
      keystore: {
        keystoreId: record.keystoreId,
        filename: record.filename,
        storeType: record.storeType,
        alias: record.alias,
        storePassword: record.storePassword,
        keyPassword: record.keyPassword,
        validityDays: record.validityDays,
        keySize: record.keySize,
        downloadUrl: `/api/keystore/${record.keystoreId}/download`
      },
      warning: KEYSTORE_LOSS_WARNING
    });
  } catch (err) {
    next(err);
  }
});

// Download Generated Keystore Endpoint
app.get('/api/keystore/:keystoreId/download', (req, res, next) => {
  const record = keystores.get(req.params.keystoreId);
  if (!record || !fs.existsSync(record.filePath)) {
    return res.status(404).json({
      success: false,
      error: { code: 'KEYSTORE_NOT_FOUND', message: 'Keystore not found or expired.' }
    });
  }

  record.activeReads++;
  res.setHeader('Content-Type', 'application/octet-stream');
  res.setHeader('Content-Disposition', `attachment; filename="${record.filename}"`);

  const stream = fs.createReadStream(record.filePath);
  stream.on('close', () => {
    record.downloaded = true;
    record.activeReads = Math.max(0, record.activeReads - 1);
  });
  stream.on('error', (err) => {
    record.activeReads = Math.max(0, record.activeReads - 1);
    next(err);
  });
  stream.pipe(res);
});

// APK Build Endpoint
const buildUploadFields = upload.fields([
  { name: 'websiteZip', maxCount: 1 },
  { name: 'appLogo', maxCount: 1 },
  { name: 'splashLogo', maxCount: 1 },
  { name: 'keystoreFile', maxCount: 1 }
]);

app.post('/api/build', buildUploadFields, async (req, res, next) => {
  const files = req.files || {};
  const zipFile = files.websiteZip?.[0];
  const appLogoFile = files.appLogo?.[0];
  const splashLogoFile = files.splashLogo?.[0];
  const keystoreFile = files.keystoreFile?.[0];

  const uploadedPaths = [zipFile, appLogoFile, splashLogoFile, keystoreFile]
    .filter(Boolean)
    .map((f) => f.path);

  const cleanupUploadedNow = async () => {
    for (const p of uploadedPaths) {
      await fsp.rm(p, { force: true }).catch(() => {});
    }
  };

  if (!zipFile) {
    await cleanupUploadedNow();
    return res.status(400).json({
      success: false,
      error: { code: 'MISSING_ZIP', message: 'websiteZip upload is required.' }
    });
  }

  const buildId = crypto.randomUUID();
  const buildDir = path.join(BUILDS_DIR, buildId);
  const extractDir = path.join(buildDir, 'extracted');
  const projectDir = path.join(buildDir, 'android-project');

  try {
    // 1. Validate encryption key & AI config up-front
    const encryptionKeyBuffer = getEncryptionKeyBuffer();
    getAiConfig();

    // 2. Extract and validate uploaded website ZIP
    const { webRootDir, entryHtml } = await extractAndValidateWebsiteZip(zipFile.path, extractDir);

    // 3. Parse and validate build configuration & Android permissions
    const parsed = parseAndValidateBuildConfig(req.body || {}, entryHtml);
    if (parsed.error) {
      await fsp.rm(buildDir, { recursive: true, force: true }).catch(() => {});
      await cleanupUploadedNow();
      return res.status(400).json({
        success: false,
        error: { code: parsed.code, message: parsed.error }
      });
    }

    // 4. Resolve signing keystore before starting heavy Gradle work
    const signing = await resolveSigningConfig(req.body || {}, keystoreFile, buildDir);

    // 5. Mandatory AI API Key Detection Scan (must run on every build)
    const aiScanReport = await performMandatoryApiKeyScan(webRootDir);

    // 6. Read optional uploaded logos
    const appLogoBuffer = appLogoFile ? await fsp.readFile(appLogoFile.path) : null;
    const splashLogoBuffer = splashLogoFile ? await fsp.readFile(splashLogoFile.path) : null;

    if (appLogoBuffer && !detectImageExtension(appLogoBuffer)) {
      await fsp.rm(buildDir, { recursive: true, force: true }).catch(() => {});
      await cleanupUploadedNow();
      return res.status(400).json({
        success: false,
        error: { code: 'INVALID_APP_LOGO', message: 'appLogo must be a valid PNG, JPEG, or WEBP image.' }
      });
    }
    if (splashLogoBuffer && !detectImageExtension(splashLogoBuffer)) {
      await fsp.rm(buildDir, { recursive: true, force: true }).catch(() => {});
      await cleanupUploadedNow();
      return res.status(400).json({
        success: false,
        error: { code: 'INVALID_SPLASH_LOGO', message: 'splashLogo must be a valid PNG, JPEG, or WEBP image.' }
      });
    }

    const buildRecord = {
      buildId,
      status: 'building',
      stage: 'queued',
      createdAt: new Date().toISOString(),
      createdAtMs: Date.now(),
      completedAt: null,
      expiresAt: null,
      isBuilding: true,
      activeDownloads: 0,
      buildDir,
      config: {
        appName: parsed.config.appName,
        packageName: parsed.config.packageName,
        versionName: parsed.config.versionName,
        versionCode: parsed.config.versionCode,
        orientation: parsed.config.orientation,
        internetAccess: parsed.config.internetAccess,
        permissionsCount: parsed.resolvedPermissions.length,
        permissions: parsed.resolvedPermissions.map((p) => p.id)
      },
      aiScanReport,
      encryption: null,
      signature: null,
      apkSizeBytes: null,
      apkSizeMB: null,
      apkFilename: null,
      apkPath: null,
      error: null
    };
    builds.set(buildId, buildRecord);

    const buildPromise = executeApkBuild(buildRecord, {
      buildDir,
      extractDir,
      webRootDir,
      projectDir,
      config: parsed.config,
      resolvedPermissions: parsed.resolvedPermissions,
      encryptionKeyBuffer,
      appLogoBuffer,
      splashLogoBuffer,
      signing,
      uploadedFilesToClean: uploadedPaths
    });

    // Optional synchronous binary APK return (?sync=true)
    if (req.query.sync === 'true' || req.body?.sync === 'true') {
      await buildPromise;
      if (buildRecord.status !== 'completed') {
        return res.status(500).json({
          success: false,
          buildId,
          aiScanReport,
          error: buildRecord.error
        });
      }
      return streamApkDownload(buildRecord, res, next);
    }

    // Async build response with buildId + status & download endpoints
    res.status(202).json({
      success: true,
      buildId,
      status: buildRecord.status,
      stage: buildRecord.stage,
      statusUrl: `/api/build/${buildId}/status`,
      downloadUrl: `/api/build/${buildId}/download`,
      config: buildRecord.config,
      aiScanReport,
      securityLimitationNote: SECURITY_LIMITATION_NOTE
    });
  } catch (err) {
    await fsp.rm(buildDir, { recursive: true, force: true }).catch(() => {});
    await cleanupUploadedNow();
    next(err);
  }
});

// Build Status Endpoint
app.get('/api/build/:buildId/status', (req, res) => {
  const record = builds.get(req.params.buildId);
  if (!record) {
    return res.status(404).json({
      success: false,
      error: { code: 'BUILD_NOT_FOUND', message: 'Build ID not found or expired.' }
    });
  }

  res.json({
    success: record.status !== 'failed',
    buildId: record.buildId,
    status: record.status,
    stage: record.stage,
    createdAt: record.createdAt,
    completedAt: record.completedAt,
    expiresAt: record.expiresAt ? new Date(record.expiresAt).toISOString() : null,
    config: record.config,
    aiScanReport: record.aiScanReport,
    encryption: record.encryption,
    signature: record.signature,
    apkSizeBytes: record.apkSizeBytes,
    apkSizeMB: record.apkSizeMB,
    apkFilename: record.apkFilename,
    downloadUrl: record.status === 'completed' ? `/api/build/${record.buildId}/download` : null,
    securityLimitationNote: SECURITY_LIMITATION_NOTE,
    error: record.error
  });
});

function streamApkDownload(record, res, next) {
  if (!record.apkPath || !fs.existsSync(record.apkPath)) {
    return res.status(404).json({
      success: false,
      error: { code: 'APK_EXPIRED', message: 'APK file is no longer available or has expired.' }
    });
  }

  record.activeDownloads++;
  res.setHeader('Content-Type', 'application/vnd.android.package-archive');
  res.setHeader('Content-Disposition', `attachment; filename="${record.apkFilename}"`);
  res.setHeader('Content-Length', String(record.apkSizeBytes));
  res.setHeader('X-Build-Id', record.buildId);
  res.setHeader('X-APK-Size-Bytes', String(record.apkSizeBytes));

  const stream = fs.createReadStream(record.apkPath);
  const done = () => {
    record.activeDownloads = Math.max(0, record.activeDownloads - 1);
  };
  res.on('finish', done);
  res.on('close', done);
  stream.on('error', (err) => {
    done();
    next(err);
  });
  stream.pipe(res);
}

// Direct APK Binary Download Endpoint
app.get('/api/build/:buildId/download', (req, res, next) => {
  const record = builds.get(req.params.buildId);
  if (!record) {
    return res.status(404).json({
      success: false,
      error: { code: 'BUILD_NOT_FOUND', message: 'Build ID not found or expired.' }
    });
  }

  if (record.status === 'building') {
    return res.status(409).json({
      success: false,
      error: { code: 'BUILD_IN_PROGRESS', message: `Build is still in progress (stage: ${record.stage}).` }
    });
  }

  if (record.status === 'failed') {
    return res.status(400).json({
      success: false,
      error: record.error || { code: 'BUILD_FAILED', message: 'Build failed; no APK available.' }
    });
  }

  return streamApkDownload(record, res, next);
});

// Temporary File Cleanup Endpoint
app.post('/api/cleanup', async (req, res, next) => {
  try {
    const report = await runCleanupSweep({ forceExpired: true });
    res.json({
      success: true,
      cleanedAt: new Date().toISOString(),
      report
    });
  } catch (err) {
    next(err);
  }
});

// Global Error Handler
app.use((err, req, res, next) => {
  if (res.headersSent) return next(err);

  if (err instanceof multer.MulterError) {
    const status = err.code === 'LIMIT_FILE_SIZE' ? 413 : 400;
    return res.status(status).json({
      success: false,
      error: { code: err.code, message: err.message }
    });
  }

  const status = err.statusCode || 500;
  res.status(status).json({
    success: false,
    error: {
      code: err.code || 'INTERNAL_SERVER_ERROR',
      message: err.message || 'An unexpected error occurred.'
    }
  });
});

// ============================================================================
// Server Startup & Graceful Shutdown
// ============================================================================

const server = app.listen(PORT, '0.0.0.0', () => {
  console.log(`APK Build Server listening on port ${PORT}`);
});

async function gracefulShutdown(signal) {
  if (isShuttingDown) return;
  isShuttingDown = true;
  console.log(`Received ${signal}. Gracefully shutting down...`);
  clearInterval(cleanupInterval);

  for (const child of activeChildProcesses) {
    try {
      child.kill('SIGTERM');
    } catch {
      // ignore
    }
  }

  // Clean up unfinished build directories
  for (const [, record] of builds.entries()) {
    if (record.isBuilding && record.buildDir) {
      await fsp.rm(record.buildDir, { recursive: true, force: true }).catch(() => {});
    }
  }

  server.close(() => {
    console.log('HTTP server closed.');
    process.exit(0);
  });

  setTimeout(() => {
    process.exit(1);
  }, 10000).unref();
}

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));
