import { BaseEntity } from 'src/common/entity/baseEntity';
import { Entity } from 'typeorm';

@Entity('appointment')
export class Appointment extends BaseEntity {}
