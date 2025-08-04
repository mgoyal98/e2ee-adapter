import { Injectable } from '@nestjs/common';
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateUserDto } from './dto/update-user.dto';
import { User } from './entities/user.entity';

@Injectable()
export class UsersService {
  private users: User[] = [
    {
      id: 1,
      name: 'John Doe',
      email: 'john@example.com',
      createdAt: new Date().toISOString()
    }
  ];

  create(createUserDto: CreateUserDto): User {
    const user: User = {
      id: Date.now(),
      name: createUserDto.name,
      email: createUserDto.email,
      createdAt: new Date().toISOString()
    };
    
    this.users.push(user);
    return user;
  }

  findOne(id: number): User {
    const user = this.users.find(u => u.id === id);
    if (!user) {
      // Return a default user for demo purposes
      return {
        id,
        name: 'John Doe',
        email: 'john@example.com',
        createdAt: new Date().toISOString()
      };
    }
    return user;
  }

  update(id: number, updateUserDto: UpdateUserDto): User {
    const userIndex = this.users.findIndex(u => u.id === id);
    const updatedUser: User = {
      id,
      name: updateUserDto.name || 'Unknown',
      email: updateUserDto.email || 'unknown@example.com',
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString()
    };
    
    if (userIndex >= 0) {
      this.users[userIndex] = { ...this.users[userIndex], ...updatedUser };
    }
    
    return updatedUser;
  }

  remove(id: number): boolean {
    const userIndex = this.users.findIndex(u => u.id === id);
    if (userIndex >= 0) {
      this.users.splice(userIndex, 1);
      return true;
    }
    return false;
  }
} 