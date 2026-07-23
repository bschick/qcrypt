"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.PasskeysCredentialsFileRepository = void 0;
const fs = __importStar(require("node:fs"));
const path = __importStar(require("node:path"));
const credentials_repository_1 = require("./credentials-repository");
const CREDENTIALS_DIR = path.join(__dirname, "./credentials");
class PasskeysCredentialsFileRepository {
    credentialsDir;
    constructor(credentialsDir = CREDENTIALS_DIR) {
        this.credentialsDir = credentialsDir;
        fs.mkdirSync(credentialsDir, { recursive: true });
    }
    saveCredential(credential) {
        const id = (0, credentials_repository_1.getRepositoryId)(credential);
        const filename = path.join(this.credentialsDir, `${id}.json`);
        const serialized = (0, credentials_repository_1.serializeCredential)(credential);
        fs.writeFileSync(filename, serialized);
    }
    deleteCredential(credential) {
        const id = (0, credentials_repository_1.getRepositoryId)(credential);
        const filename = path.join(this.credentialsDir, `${id}.json`);
        fs.unlink(filename, () => { });
    }
    loadCredentials() {
        const files = fs.readdirSync(this.credentialsDir);
        return files.flatMap((file) => {
            try {
                const filename = path.join(this.credentialsDir, file);
                const serialized = fs.readFileSync(filename, "utf-8");
                return [(0, credentials_repository_1.deserializeCredential)(serialized)];
            }
            catch {
                return [];
            }
        });
    }
}
exports.PasskeysCredentialsFileRepository = PasskeysCredentialsFileRepository;
