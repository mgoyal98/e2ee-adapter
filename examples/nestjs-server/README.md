# NestJS Server Example with E2EE

This example demonstrates how to use the E2EE adapter with a proper NestJS application structure.

## Features

- ✅ **Proper NestJS Architecture**: Controllers, Services, DTOs, and Entities
- ✅ **E2EE Interceptor**: Global encryption/decryption for all endpoints
- ✅ **TypeScript Support**: Full type safety with interfaces and DTOs
- ✅ **Modular Structure**: Separate modules for different features
- ✅ **RESTful API**: Standard CRUD operations for users

## Project Structure

```
src/
├── app.controller.ts          # Main app controller
├── app.module.ts             # Root module with E2EE interceptor
├── app.service.ts            # App service
├── main.ts                   # Application entry point
└── users/                    # Users feature module
    ├── dto/
    │   ├── create-user.dto.ts
    │   └── update-user.dto.ts
    ├── entities/
    │   └── user.entity.ts
    ├── users.controller.ts   # Users controller
    ├── users.service.ts      # Users service
    └── users.module.ts       # Users module
```

## API Endpoints

### Health Check
- `GET /health` - Health check endpoint (excluded from E2EE)

### Echo
- `POST /api/echo` - Echo endpoint for testing E2EE

### Users
- `POST /api/users` - Create a new user
- `GET /api/users/:id` - Get user by ID
- `PUT /api/users/:id` - Update user by ID
- `DELETE /api/users/:id` - Delete user by ID

## E2EE Configuration

The E2EE interceptor is configured globally in `app.module.ts`:

```typescript
{
  provide: APP_INTERCEPTOR,
  useFactory: async () => {
    return new E2EEInterceptor({
      config: {
        keys: await generateMultipleKeyPairs(['domain1']),
        enableRequestDecryption: true,
        enableResponseEncryption: true,
        excludePaths: ['/health', '/keys'],
        excludeMethods: ['HEAD', 'OPTIONS'],
      },
      onError: (error, req, res) => {
        console.error('🔒 E2EE Error:', error.message);
      },
      onDecrypt: (decryptedData, req) => {
        console.log('🔓 Request decrypted successfully');
      },
      onEncrypt: (encryptedData, res) => {
        console.log('🔒 Response encrypted successfully');
      },
    });
  },
}
```

## Running the Example

1. **Install dependencies:**
   ```bash
   npm install
   ```

2. **Build the project:**
   ```bash
   npm run build
   ```

3. **Start the server:**
   ```bash
   npm start
   ```

4. **Development mode:**
   ```bash
   npm run dev
   ```

## Testing with Client

Use the provided client examples to test the E2EE functionality:

- `../client-example/` - Vanilla JavaScript client
- `../vanilla-js-client/` - Alternative client implementation

## Best Practices Implemented

1. **Separation of Concerns**: Controllers handle HTTP requests, services handle business logic
2. **DTOs**: Proper data transfer objects for input validation
3. **Entities**: Clear data models for the application
4. **Modules**: Feature-based module organization
5. **Dependency Injection**: Proper use of NestJS DI container
6. **TypeScript**: Full type safety throughout the application

## Notes

- The `/health` endpoint is excluded from E2EE for monitoring purposes
- All other endpoints require proper E2EE headers for encryption/decryption
- The interceptor handles both request decryption and response encryption automatically 