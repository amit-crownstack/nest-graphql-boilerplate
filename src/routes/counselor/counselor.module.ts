import { Module } from '@nestjs/common';
import { CounselorController } from './counselor.controller';

@Module({
  controllers: [CounselorController]
})
export class CounselorModule {}
