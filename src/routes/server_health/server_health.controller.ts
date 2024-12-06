import { Controller, Get, Render } from '@nestjs/common';
import { ApiTags } from '@nestjs/swagger';
import { ServerHealthService } from './provider/server_health.service';

@Controller('health')
@ApiTags('Server Health')
export class ServerHealthController {
  constructor(private readonly healthService: ServerHealthService) {}

  @Get()
  @Render('index')
  getServerHealthCheck() {
    const healthStatus = this.healthService.getHealthStatus();
    const serverUtilization = this.healthService.getServerUtilization();
    const currentDate = new Date().toLocaleString(); // Pass current date to the template

    return {
      healthStatus: healthStatus ? 'WORKING' : 'NOT RESPONDING',
      serverUtilization: serverUtilization,
      timestamp: new Date(),
      currentDate: currentDate,
    };
  }
}
