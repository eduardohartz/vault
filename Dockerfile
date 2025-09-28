FROM node:22.16.0

WORKDIR /usr/src/app

COPY package*.json ./

RUN npm install --frozen-lockfile

RUN npx prisma generate

COPY . .

RUN npm run build

EXPOSE ${PORT}

RUN apt-get update && apt-get install -y postgresql-client

COPY entrypoint.sh /usr/src/app/entrypoint.sh
RUN chmod +x /usr/src/app/entrypoint.sh

ENTRYPOINT ["/usr/src/app/entrypoint.sh"]