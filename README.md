# wagenix

> Windows 原生 [agenix](https://github.com/ryantm/agenix) 兼容工具：编辑、解密、重加密 age secrets，直接复用 NixOS 生态的 `secrets.nix` 规则文件。

wagenix 让你在 Windows 上使用与 [agenix](https://github.com/ryantm/agenix) 完全相同的 CLI 和规则文件管理加密 secret，**不需要**额外维护 JSON / TOML / YAML 规则。同一份 `secrets.nix` 既可用于 NixOS 部署，也可用于本工具。

- **零额外配置**：直接解析原版 `secrets.nix`（内置 Nix 子集解析器），NixOS 和 Windows 共用一份规则
- **CLI 兼容**：`-e` / `-d` / `-r` / `-i` 参数与原版 agenix 一致
- **自动身份查找**：未指定私钥时自动使用 `%USERPROFILE%\.ssh\id_ed25519` → `id_rsa`
- **自愈测试**：集成测试运行前自动重置测试数据，不受手动测试影响

## Features

- **编辑即加密**：`wagenix -e` 解密到临时文件 → 打开 `$EDITOR` → 保存后按规则中的公钥自动加密写回；未修改自动跳过
- **解密到 stdout**：`wagenix -d` 直接输出明文，自动识别 binary 与 armored 格式
- **Rekey**：`wagenix -r` 遍历 `secrets.nix` 中所有 secret 重新加密（公钥变更后一键更新）
- **stdin 管道**：`echo secret | wagenix -e file.age` 支持非交互写入（对齐 agenix 的 `cp /dev/stdin` 行为）
- **armor 支持**：规则中的 `armor = true` 输出 Base64 ASCII 格式，便于 diff
- **原生 Windows**：Rust 编写，编译为独立 `.exe`，无运行时依赖

## 快速开始

### 构建

```powershell
cargo build --release
# 产物: target\release\wagenix.exe
```

### 准备规则文件

在 secrets 目录创建 `secrets.nix`（与原版 agenix 格式一致）：

```nix
let
  user1 = "ssh-ed25519 AAAA...";
  system1 = "ssh-ed25519 AAAA...";
in
{
  "secret1.age".publicKeys = [ user1 system1 ];
  "armored-secret.age" = {
    publicKeys = [ user1 ];
    armor = true;
  };
}
```

> [!NOTE]
> wagenix 内置的解析器支持 agenix 规则文件中实际使用的 Nix 语法子集（`let...in`、字符串、列表、attrset、attrpath、`++` 拼接、布尔）。函数、`builtins` 等完整 Nix 特性会给出清晰错误提示。

### 使用

```powershell
# 解密到 stdout
wagenix -d secret1.age

# 编辑（解密 → 编辑器 → 自动加密）
wagenix -e secret1.age

# 指定私钥
wagenix -e secret1.age -i C:\Users\you\.ssh\id_ed25519

# 通过 stdin 写入
echo "my secret" | wagenix -e secret1.age

# rekey 所有 secrets
wagenix -r

# 指定规则文件（默认 ./secrets.nix）
$env:RULES = "D:\secrets\secrets.nix"
wagenix -e secret1.age
```

### CLI 参考

```
wagenix -e FILE [-i PRIVATE_KEY]
wagenix -r [-i PRIVATE_KEY]
wagenix -d FILE [-i PRIVATE_KEY]

options:
-h, --help              show help
-e, --edit FILE         edits FILE using $EDITOR
-r, --rekey             re-encrypts all secrets with specified recipients
-d, --decrypt FILE      decrypts FILE to STDOUT
-i, --identity          identity to use when decrypting
-v, --verbose           verbose output
```

| 环境变量 | 说明 | 默认值 |
|---|---|---|
| `EDITOR` / `VISUAL` | 编辑命令 | VS Code (`code --wait`) → notepad |
| `RULES` | 规则文件路径 | `./secrets.nix` |

> [!TIP]
> 身份查找顺序：`-i` 显式指定 → `%USERPROFILE%\.ssh\id_ed25519` → `%USERPROFILE%\.ssh\id_rsa`（WSL 下对应 `~/.ssh`）。

## 身份与规则

### 使用 SSH 密钥

- **加密**：`secrets.nix` 中的 `publicKeys` 即为收件人公钥
- **解密**：需要对应私钥，通过 `-i` 指定或使用默认身份

公钥获取方式：

```powershell
ssh-keyscan <host>                          # 目标机器公钥
# 或 GitHub 用户公钥: https://github.com/<username>.keys
```

> [!WARNING]
> `-i` 需要的是**私钥**文件（`-----BEGIN OPENSSH PRIVATE KEY-----`），公钥文件（`.pub`）只能用于加密，不能用于解密。

### 不支持的 Nix 特性

解析器仅覆盖 agenix 规则文件的实际用法。若你的 `secrets.nix` 使用了函数、`builtins`、`map` 等特性，可以：

1. 简化规则文件为纯数据（推荐）
2. 或在有 Nix 的机器上用 `nix-instantiate --eval` 验证结果一致性

## 项目结构

```
wagenix/
├── src/
│   ├── main.rs         # CLI（agenix 兼容参数）+ edit/rekey/decrypt 流程
│   ├── nix.rs          # Nix 子集 lexer/parser/evaluator + 单元测试
│   └── crypto.rs       # age 加解密封装（SSH 密钥、armor、原子写）
├── test/               # 测试数据（密钥、规则、预加密文件）
│   ├── id_ed25519      # 测试专用私钥（仅用于测试）
│   ├── id_ed25519.pub
│   ├── secrets.nix     # 规则（测试密钥 + 本机 Windows/WSL 公钥）
│   ├── secret1.age     # 预加密 secret（内容: hello wagenix test）
│   └── armored-secret.age
└── tests/
    └── integration.rs  # 端到端集成测试（18 个）
```

## 测试

```powershell
cargo test
```

- **单元测试**（`src/nix.rs`）：Nix 子集解析器，覆盖 let 绑定、`++` 拼接、attrpath、注释及错误场景
- **集成测试**（`tests/integration.rs`）：端到端调用二进制，覆盖解密（binary/armored）、编辑 roundtrip、stdin 管道、rekey、默认身份查找、错误场景

> [!NOTE]
> **自愈机制**：手动测试可能改写 `test/*.age` 的内容。每个集成测试开始前会自动覆写为标准明文内容再执行断言，因此无论之前手动改过什么，`cargo test` 都会先重置数据再验证。测试后 `test/*.age` 保持标准内容。

### 手动测试

`test/secrets.nix` 中配置了三个 recipient，可分别验证不同身份：

| 身份 | 公钥来源 | 场景 |
|---|---|---|
| `testKey` | `test/id_ed25519` | 自动化测试，始终用 `-i test/id_ed25519` |
| `localKey` | Windows `%USERPROFILE%\.ssh\id_ed25519` | Windows 上不带 `-i` 手动测试 |
| `wslKey` | WSL `~/.ssh/id_ed25519` | WSL 上不带 `-i` 手动测试 |

```bash
# WSL
cd test
export RULES=secrets.nix
cargo run -- -d secret1.age          # -> hello wagenix test
```

```powershell
# Windows
cd D:\wagenix\test
$env:RULES = "D:\wagenix\test\secrets.nix"
wagenix -d secret1.age               # -> hello wagenix test
```

## 与 agenix 的对比

| 特性 | agenix | wagenix |
|---|---|---|
| 平台 | Linux / macOS (NixOS) | Windows 原生 |
| 规则文件 | `secrets.nix` | `secrets.nix`（相同格式） |
| 编辑 / 解密 / rekey | ✅ | ✅ |
| NixOS 模块（激活时挂载） | ✅ | ❌ 不适用（Windows 无 NixOS） |
| home-manager 模块 | ✅ | ❌ 不适用 |
| ssh-agent 支持 | ❌（age CLI 限制） | 计划中 |

## 路线图

- [ ] ssh-agent 支持（解决密码保护密钥需重复输入的痛点）
- [ ] GUI 封装（右键菜单 / 文件关联集成）
- [ ] CI 自动构建 Windows release

## 致谢

- 基于 [agenix](https://github.com/ryantm/agenix) 的设计与 CLI 规范
- 加密由 [age](https://github.com/FiloSottile/age) 提供（Rust 实现 [rage](https://github.com/str4d/rage)）
