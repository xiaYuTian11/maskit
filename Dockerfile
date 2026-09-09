# ==========================================
# 阶段 1: 前端静态资源构建
# ==========================================
FROM node:20-alpine AS frontend-builder
WORKDIR /build/frontend

COPY frontend/package*.json ./
# 只认 lockfile：回退到 npm install 会让镜像内依赖与仓库锁定版本漂移
RUN npm ci --prefer-offline

COPY frontend/ ./
RUN npm run build

# ==========================================
# 阶段 2: Python 核心脱敏代理引擎与 Web 控制台
# ==========================================
FROM python:3.13-slim AS runner

WORKDIR /app

# MASKIT_PANEL_HOST=0.0.0.0 会让引擎进入「远程模式」：Host 校验放开、Origin 同源校验，
# 面板 API 仍必须带 X-Shield-Token。生产部署请设置 MASKIT_PANEL_TOKEN（≥16 位），
# 否则每次启动随机生成并打印到容器日志（docker logs maskit）。
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    LLM_SHIELD_DATA_DIR=/data \
    MASKIT_WEB_DIST=/app/web_dist \
    MASKIT_PANEL_HOST=0.0.0.0 \
    MASKIT_LISTEN_HOST=0.0.0.0

# 运行时系统工具：net-tools（端口占用探测）、procps（进程识别）、curl（HEALTHCHECK）
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    net-tools \
    procps \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --create-home --home-dir /home/maskit maskit \
    && mkdir -p /data && chown maskit:maskit /data

# 安装 Python 核心依赖
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# 拷贝核心引擎文件（.dockerignore 已排除本机事件库 / token / 配置备份）
COPY engine/ ./

# 从阶段 1 拷贝构建好的前端静态页面到 web_dist
COPY --from=frontend-builder /build/frontend/dist /app/web_dist

# 持久化数据目录（config.json / 事件库 / mitmproxy CA 证书）
VOLUME ["/data"]

# 5801: Web 控制面板 API / UI
# 18701-18710: 默认各模型反向代理端口（compose 里按需映射）
EXPOSE 5801 18701 18702 18703 18704 18705 18706 18707 18708 18709 18710

# /healthz 不需要 token，只回存活状态
HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -fsS http://127.0.0.1:5801/healthz || exit 1

# 非 root 运行：面板可改上游/注入头，容器逃逸面越小越好
USER maskit

CMD ["python", "engine_entry.py"]
