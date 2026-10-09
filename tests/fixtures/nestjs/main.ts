import { NestFactory } from '@nestjs/core';
const app = await NestFactory.create(AppModule);
app.setGlobalPrefix('api');
