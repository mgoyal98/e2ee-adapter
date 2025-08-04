import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import * as bodyParser from 'body-parser';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  
  // Enable CORS
  app.enableCors();

  app.use(bodyParser.text({ type: 'text/plain' }));
  
  const port = process.env.PORT || 3001;
  await app.listen(port);
  
  console.log(`🚀 E2EE NestJS server running on http://localhost:${port}`);
  console.log(`📊 Health check: http://localhost:${port}/health`);
  console.log(`🔑 Public keys: http://localhost:${port}/keys`);
  console.log(`\n📖 API Endpoints:`);
  console.log(`   POST /api/users - Create user (encrypted)`);
  console.log(`   GET  /api/users/:id - Get user (encrypted)`);
  console.log(`   PUT  /api/users/:id - Update user (encrypted)`);
  console.log(`   DELETE /api/users/:id - Delete user (encrypted)`);
}

bootstrap().catch(console.error); 