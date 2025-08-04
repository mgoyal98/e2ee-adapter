import { Module } from '@nestjs/common';
import { APP_INTERCEPTOR } from '@nestjs/core';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { UsersModule } from './users/users.module';
import { E2EEInterceptor } from '../../../dist';
import { config, generateKeys } from './config';

@Module({
  imports: [UsersModule],
  controllers: [AppController],
  providers: [
    AppService,
    {
      provide: APP_INTERCEPTOR,
      useFactory: async () => {
        await generateKeys();
        return new E2EEInterceptor({
          config: {
            keys: config.keys,

            enableRequestDecryption: true,
            enableResponseEncryption: false,

            allowEmptyRequestBody: true,

            excludePaths: ['/health', '/keys'],
            excludeMethods: ['HEAD', 'OPTIONS'],
          },
          onError: (error, req, res) => {
            console.error('🔒 E2EE Error:', error.message);
          },
          onDecrypt: (decryptedData, req) => {
            console.log('🔓 Request decrypted successfully');
          },
          onEncrypt: (encryptedData, res) => {
            console.log('🔒 Response encrypted successfully');
          },
        });
      },
    },
  ],
})
export class AppModule {}
