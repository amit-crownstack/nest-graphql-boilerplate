import { BaseEntity } from 'src/common/entity/baseEntity';
import { Column, Entity } from 'typeorm';

@Entity('counselor')
export class CounselorEntity extends BaseEntity {
  @Column({ type: 'varchar', nullable: false })
  name: string;
}
