FROM node:18-alpine

WORKDIR /app

# Install dependencies first (for faster caching)
COPY package*.json ./
RUN npm install

# Copy code
COPY . .

# Expose Next.js port
EXPOSE 3000

ENV PORT=3000
ENV HOSTNAME="0.0.0.0"

# Start Dev server
CMD ["npm", "run", "dev"]
