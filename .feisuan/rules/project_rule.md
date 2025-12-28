
# JaySenWxapkg 项目开发规范指南

## 一、项目基本信息

- **项目名称**：JaySenWxapkg
- **操作系统**：Windows 11
- **工作目录**：`E:\java_project\A_BurpExtender\JaySenWxapkg`
- **代码作者**：lsj31
- **当前时间**：2025-12-22 10:32:09

## 二、技术栈要求

- **JDK 版本**：24.0.1
- **构建工具**：Gradle
- **核心依赖**：
  - `net.portswigger.burp.extensions:montoya-api:2025.8`（仅编译时依赖）
  - `com.squareup.okhttp3:okhttp:4.12.0`
  - `com.fasterxml.jackson.core:jackson-databind:2.16.1`

## 三、项目目录结构

```
JaySenWxapkg/
├── docs/                    # 文档目录
├── gradle/                  # Gradle 配置目录
│   └── wrapper/            # Gradle Wrapper 文件
└── src/                    # 源代码目录
    ├── main/               # 主代码目录
    │   └── java/          # Java 源代码
    └── test/              # 测试代码目录
        └── java/          # Java 测试代码
```

## 四、Java 编码规范

### 编译配置

- **源代码兼容性**：Java 21
- **目标代码兼容性**：Java 21
- **文件编码**：UTF-8

### 命名规范

| 类型       | 命名方式             | 示例                  |
|------------|----------------------|-----------------------|
| 类名       | UpperCamelCase       | `WxapkgProcessor`     |
| 方法/变量  | lowerCamelCase       | `processPackage()`    |
| 常量       | UPPER_SNAKE_CASE     | `MAX_BUFFER_SIZE`     |

### 注释规范

- 所有类、方法、字段需添加 **Javadoc** 注释，使用中文注释
- 关键业务逻辑需添加行内注释说明

## 五、Burp 扩展开发规范

### 依赖管理

- Burp Montoya API 仅作为编译时依赖（`compileOnly`）
- 实际运行时依赖由 Burp 提供

### 打包配置

- 生成的 JAR 文件名格式：`JaySenWxapkg-版本号.jar`
- 打包时排除重复文件（`duplicatesStrategy = DuplicatesStrategy.EXCLUDE`）
- 包含所有运行时依赖

## 六、编码原则总结

| 原则       | 说明                                       |
|------------|--------------------------------------------|
| **SOLID**  | 高内聚、低耦合，增强可维护性与可扩展性     |
| **DRY**    | 避免重复代码，提高复用性                   |
| **KISS**   | 保持代码简洁易懂                           |
| **YAGNI**  | 不实现当前不需要的功能                     |
| **OWASP**  | 防范常见安全漏洞，如数据泄露等             |

## 七、开发建议

1. **模块化设计**：将不同功能模块分离，便于维护和扩展
2. **异常处理**：合理使用异常处理机制，避免程序崩溃
3. **日志记录**：添加适当的日志记录，便于调试和问题追踪
4. **配置管理**：使用配置文件管理可变参数，避免硬编码
5. **版本控制**：遵循语义化版本规范，便于版本管理
