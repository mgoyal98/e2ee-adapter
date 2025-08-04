import { Controller, Get, Post, Body } from '@nestjs/common';
import { AppService } from './app.service';
import { config } from './config';

@Controller()
export class AppController {
  constructor(private readonly appService: AppService) {}

  @Get('health')
  getHealth(): { status: string; timestamp: string } {
    return {
      status: 'OK',
      timestamp: new Date().toISOString(),
    };
  }

  @Post('api/echo')
  echo(@Body() data: any): any {
    console.log('📝 Echo endpoint called with data:', data);
    return {
      success: true,
      data,
      timestamp: new Date().toISOString(),
      message: 'Data echoed successfully',
    };
  }

  @Get('keys')
  keys(): any {
    const publicKeys: Record<string, string> = {};

    Object.keys(config.keys).forEach((domain) => {
      publicKeys[domain] = config.keys[domain].publicKey;
    });

    return {
      keys: publicKeys,
      keySize: 2048,
    };
  }
}
