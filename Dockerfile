FROM mhart/alpine-node:4

WORKDIR /app
ADD package.json .
RUN npm install --production
ADD . .

ENV COMPONENT="permissions-migration"
ENV PORT=3000
EXPOSE 3000
CMD ["node", "permissions-migration.js"]