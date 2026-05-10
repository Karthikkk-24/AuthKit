import { Module, Global } from '@nestjs/common';
import { EmailService } from './email.service';
import { AppConfigModule } from '../config/config.module';

@Global()
@Module({
  imports: [AppConfigModule],
  providers: [EmailService],
  exports: [EmailService],
})
export class EmailModule {}
