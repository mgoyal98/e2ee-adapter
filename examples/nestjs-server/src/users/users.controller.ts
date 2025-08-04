import { Controller, Get, Post, Put, Delete, Body, Param } from '@nestjs/common';
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateUserDto } from './dto/update-user.dto';
import { User } from './entities/user.entity';
import { UsersService } from './users.service';

@Controller('api/users')
export class UsersController {
  constructor(private readonly usersService: UsersService) {}

  @Post()
  create(@Body() createUserDto: CreateUserDto) {
    console.log('📝 Creating user with data:', createUserDto);
    
    const user = this.usersService.create(createUserDto);
    
    return {
      success: true,
      user,
      message: 'User created successfully'
    };
  }

  @Get(':id')
  findOne(@Param('id') id: string) {
    const userId = parseInt(id);
    console.log('👤 Fetching user with ID:', userId);
    
    const user = this.usersService.findOne(userId);
    
    return {
      success: true,
      user
    };
  }

  @Put(':id')
  update(@Param('id') id: string, @Body() updateUserDto: UpdateUserDto) {
    const userId = parseInt(id);
    console.log('✏️ Updating user with ID:', userId, 'Data:', updateUserDto);
    
    const user = this.usersService.update(userId, updateUserDto);
    
    return {
      success: true,
      user,
      message: 'User updated successfully'
    };
  }

  @Delete(':id')
  remove(@Param('id') id: string) {
    const userId = parseInt(id);
    console.log('🗑️ Deleting user with ID:', userId);
    
    const deleted = this.usersService.remove(userId);
    
    return {
      success: deleted,
      message: deleted ? `User ${userId} deleted successfully` : `User ${userId} not found`
    };
  }
} 