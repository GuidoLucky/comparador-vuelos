FROM node:18

RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    libreoffice \
    fonts-dejavu-core \
    && rm -rf /var/lib/apt/lists/*

RUN pip3 install reportlab python-pptx openpyxl --break-system-packages

WORKDIR /app
COPY package*.json ./
RUN npm install
COPY . .

EXPOSE 8080
CMD ["node", "server.js"]
