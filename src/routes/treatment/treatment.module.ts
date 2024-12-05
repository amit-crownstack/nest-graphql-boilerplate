import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { UserEntity } from '../users/entity/user.entity';
import { TreatmentController } from './treatment.controller';
import { TreatmentService } from './provider/treatment.service';

@Module({
  imports: [TypeOrmModule.forFeature([UserEntity])],
  controllers: [TreatmentController],
  providers: [TreatmentService],
})
export class TreatmentModule {}
