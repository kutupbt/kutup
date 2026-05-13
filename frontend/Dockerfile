FROM node:20-alpine AS builder

# Pin to the pnpm version declared in package.json's `packageManager` field.
# `corepack prepare pnpm@latest --activate` was hitting an npm-registry tag
# lookup that fails inside this builder; npm-installing the exact version
# bypasses corepack's signature/tag-lookup path entirely.
RUN npm install -g pnpm@9.1.1

WORKDIR /app
COPY package.json pnpm-lock.yaml* ./
RUN pnpm install --frozen-lockfile

COPY . .
RUN pnpm run build

FROM nginx:alpine
COPY --from=builder /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 80
