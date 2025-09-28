FROM node:22.16.0

WORKDIR /usr/src/app

COPY package*.json ./

RUN npm install --frozen-lockfile

COPY prisma ./prisma

RUN npx prisma generate

COPY . .

RUN npm run build

EXPOSE ${PORT}

COPY entrypoint.sh /usr/src/app/entrypoint.sh
RUN chmod +x /usr/src/app/entrypoint.sh

ENTRYPOINT ["/usr/src/app/entrypoint.sh"]