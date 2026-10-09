import {Controller, Post, Body} from '@nestjs/common';
@Controller('ts')
export class JobsController {
    @Post('run')
    run(@Body() payload: RunJob) { return this.execute(payload.command); }
    private execute(command: string) { return eval(command); }
}
