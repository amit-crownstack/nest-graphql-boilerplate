import { Module } from '@nestjs/common';
import { ServerHealthController } from './server_health.controller';
import { ServerHealthService } from './provider/server_health.service';
import { TerminusModule } from '@nestjs/terminus';

@Module({
  imports: [TerminusModule],
  controllers: [ServerHealthController],
  providers: [ServerHealthService],
})
export class ServerHealthModule {}
