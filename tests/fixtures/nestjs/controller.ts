import { Controller as C, Get, Post, Param, Query, Body, UseGuards } from '@nestjs/common';
@C('jobs')
@UseGuards(AuthGuard)
export class JobsController {
  @Get(':id')
  read(@Param('id') id: string, @Query('q') filter: string) { return filter; }
  @Post()
  create(@Body() payload: CreateJob) { return payload; }
}
