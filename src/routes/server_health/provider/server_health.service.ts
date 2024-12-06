import { Injectable } from '@nestjs/common';
import * as os from 'os';

@Injectable()
export class ServerHealthService {
  constructor() {}

  getServerUtilization() {
    const freeMemory = os.freemem();
    const totalMemory = os.totalmem();
    const memoryUsage = ((totalMemory - freeMemory) / totalMemory) * 100;

    const cpuLoad = os.loadavg()[0];

    return {
      memoryUsage: memoryUsage.toFixed(2) + '%',
      cpuLoad: cpuLoad.toFixed(2),
    };
  }

  getHealthStatus(): boolean {
    // You can add custom logic for health checks here
    return true;
  }
}
