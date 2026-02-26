/*
File: test_integration.tpl.js
Purpose: Integration test patterns and examples
Generated for: {{PROJECT_NAME}}
*/

const {
    getPrisma,
    setupDatabase,
    teardownDatabase,
    cleanDatabase,
    createUser,
    createPost,
    createAuthToken,
    createTestClient,
    faker,
} = require('./test_fixtures');

const { assertResponse, assertExistsInDb, waitFor } = require('./test_helpers');

// Import your app
// const app = require('../src/app');

// ============================================================================
// Setup
// ============================================================================

describe('Integration Tests', () => {
    let prisma;
    let client;

    beforeAll(async () => {
        prisma = await setupDatabase();
        // client = createTestClient(app);
    });

    afterAll(async () => {
        await teardownDatabase();
    });

    beforeEach(async () => {
        await cleanDatabase();
    });

    // ============================================================================
    // Authentication Flow Tests
    // ============================================================================

    describe('Authentication Flow', () => {
        describe('POST /api/auth/register', () => {
            it('should register a new user', async () => {
                const userData = {
                    email: 'newuser@test.com',
                    username: 'newuser',
                    password: 'SecurePassword123!',
                    fullName: 'New User',
                };

                const response = await client.post('/api/auth/register', userData);

                assertResponse(response)
                    .created()
                    .hasKey('user', 'accessToken')
                    .dataContains({ email: userData.email });

                await assertExistsInDb(prisma, 'user', { email: userData.email });
            });

            it('should reject duplicate email', async () => {
                const existingUser = await createUser(prisma, { email: 'existing@test.com' });

                const response = await client.post('/api/auth/register', {
                    email: 'existing@test.com',
                    username: 'newuser',
                    password: 'Password123!',
                });

                assertResponse(response)
                    .badRequest()
                    .hasError('EMAIL_EXISTS');
            });

            it('should validate password requirements', async () => {
                const response = await client.post('/api/auth/register', {
                    email: 'test@test.com',
                    username: 'testuser',
                    password: '123', // Too weak
                });

                assertResponse(response)
                    .unprocessable()
                    .hasError('VALIDATION_ERROR');
            });
        });

        describe('POST /api/auth/login', () => {
            it('should login with valid credentials', async () => {
                const password = 'TestPassword123!';
                const user = await createUser(prisma, {
                    email: 'test@test.com',
                    // In real tests, hash the password properly
                });

                const response = await client.post('/api/auth/login', {
                    email: user.email,
                    password,
                });

                assertResponse(response)
                    .ok()
                    .hasKey('accessToken', 'refreshToken', 'user');
            });

            it('should reject invalid credentials', async () => {
                const user = await createUser(prisma);

                const response = await client.post('/api/auth/login', {
                    email: user.email,
                    password: 'wrongpassword',
                });

                assertResponse(response)
                    .unauthorized()
                    .hasError('INVALID_CREDENTIALS');
            });

            it('should reject inactive user', async () => {
                const user = await createUser(prisma, { isActive: false });

                const response = await client.post('/api/auth/login', {
                    email: user.email,
                    password: 'TestPassword123!',
                });

                assertResponse(response)
                    .forbidden()
                    .hasError('ACCOUNT_DISABLED');
            });
        });

        describe('Protected Routes', () => {
            it('should access protected route with valid token', async () => {
                const user = await createUser(prisma);
                const token = createAuthToken(user.id);

                const response = await client.authGet('/api/users/me', token);

                assertResponse(response)
                    .ok()
                    .dataContains({ id: user.id, email: user.email });
            });

            it('should reject expired token', async () => {
                const user = await createUser(prisma);
                const token = createAuthToken(user.id, { expiresIn: '-1h' });

                const response = await client.authGet('/api/users/me', token);

                assertResponse(response).unauthorized();
            });

            it('should reject missing token', async () => {
                const response = await client.get('/api/users/me');

                assertResponse(response).unauthorized();
            });
        });
    });

    // ============================================================================
    // CRUD Operations Tests
    // ============================================================================

    describe('CRUD Operations', () => {
        let user;
        let token;

        beforeEach(async () => {
            user = await createUser(prisma);
            token = createAuthToken(user.id);
        });

        describe('Posts', () => {
            describe('POST /api/posts', () => {
                it('should create a new post', async () => {
                    const postData = {
                        title: 'Test Post',
                        content: 'This is the content.',
                        status: 'draft',
                    };

                    const response = await client.authPost('/api/posts', postData, token);

                    assertResponse(response)
                        .created()
                        .dataContains({
                            title: postData.title,
                            authorId: user.id,
                        });

                    const post = response.body.data;
                    await assertExistsInDb(prisma, 'post', { id: post.id });
                });
            });

            describe('GET /api/posts/:id', () => {
                it('should get a post by id', async () => {
                    const post = await createPost(prisma, user.id);

                    const response = await client.authGet(`/api/posts/${post.id}`, token);

                    assertResponse(response)
                        .ok()
                        .dataContains({ id: post.id, title: post.title });
                });

                it('should return 404 for non-existent post', async () => {
                    const response = await client.authGet('/api/posts/99999', token);

                    assertResponse(response).notFound();
                });
            });

            describe('PATCH /api/posts/:id', () => {
                it('should update a post', async () => {
                    const post = await createPost(prisma, user.id);

                    const response = await client.authPatch(
                        `/api/posts/${post.id}`,
                        { title: 'Updated Title' },
                        token
                    );

                    assertResponse(response)
                        .ok()
                        .dataContains({ title: 'Updated Title' });
                });

                it('should reject update by non-owner', async () => {
                    const otherUser = await createUser(prisma);
                    const post = await createPost(prisma, otherUser.id);

                    const response = await client.authPatch(
                        `/api/posts/${post.id}`,
                        { title: 'Hacked' },
                        token
                    );

                    assertResponse(response).forbidden();
                });
            });

            describe('DELETE /api/posts/:id', () => {
                it('should delete a post', async () => {
                    const post = await createPost(prisma, user.id);

                    const response = await client.authDelete(`/api/posts/${post.id}`, token);

                    assertResponse(response).noContent();

                    // Verify soft delete
                    const deleted = await prisma.post.findUnique({ where: { id: post.id } });
                    expect(deleted.isDeleted).toBe(true);
                });
            });

            describe('GET /api/posts', () => {
                it('should list posts with pagination', async () => {
                    // Create 25 posts
                    for (let i = 0; i < 25; i++) {
                        await createPost(prisma, user.id);
                    }

                    const response = await client.authGet('/api/posts?page=1&perPage=10', token);

                    assertResponse(response)
                        .ok()
                        .dataLength(10)
                        .paginationEquals({
                            page: 1,
                            perPage: 10,
                            total: 25,
                        });
                });

                it('should filter posts by status', async () => {
                    await createPost(prisma, user.id, { status: 'published' });
                    await createPost(prisma, user.id, { status: 'published' });
                    await createPost(prisma, user.id, { status: 'draft' });

                    const response = await client.authGet('/api/posts?status=published', token);

                    assertResponse(response)
                        .ok()
                        .dataLength(2);
                });

                it('should search posts by title', async () => {
                    await createPost(prisma, user.id, { title: 'JavaScript Guide' });
                    await createPost(prisma, user.id, { title: 'Python Guide' });
                    await createPost(prisma, user.id, { title: 'Other Topic' });

                    const response = await client.authGet('/api/posts?search=Guide', token);

                    assertResponse(response)
                        .ok()
                        .dataLength(2);
                });
            });
        });
    });

    // ============================================================================
    // Webhook Tests
    // ============================================================================

    describe('Webhooks', () => {
        describe('POST /api/webhooks/stripe', () => {
            it('should handle subscription created event', async () => {
                const user = await createUser(prisma, { stripeCustomerId: 'cus_test' });

                const payload = {
                    type: 'customer.subscription.created',
                    data: {
                        object: {
                            id: 'sub_123',
                            customer: 'cus_test',
                            status: 'active',
                            items: {
                                data: [{ price: { id: 'price_pro' } }],
                            },
                        },
                    },
                };

                // In real tests, compute proper Stripe signature
                const response = await client.post('/api/webhooks/stripe', payload, {
                    'Stripe-Signature': 'test_signature',
                });

                assertResponse(response).ok();

                // Verify subscription was created
                await assertExistsInDb(prisma, 'subscription', {
                    userId: user.id,
                    stripeSubscriptionId: 'sub_123',
                });
            });
        });
    });

    // ============================================================================
    // File Upload Tests
    // ============================================================================

    describe('File Uploads', () => {
        let user;
        let token;

        beforeEach(async () => {
            user = await createUser(prisma);
            token = createAuthToken(user.id);
        });

        it('should upload a file', async () => {
            const response = await client
                .authPost('/api/files/upload', {}, token)
                .attach('file', Buffer.from('Hello, World!'), 'test.txt');

            assertResponse(response)
                .created()
                .hasKey('id', 'url', 'filename');
        });

        it('should reject file too large', async () => {
            const largeBuffer = Buffer.alloc(11 * 1024 * 1024); // 11 MB

            const response = await client
                .authPost('/api/files/upload', {}, token)
                .attach('file', largeBuffer, 'large.bin');

            assertResponse(response).status(413);
        });

        it('should reject invalid file type', async () => {
            const response = await client
                .authPost('/api/files/upload', {}, token)
                .attach('file', Buffer.from('malicious'), 'virus.exe');

            assertResponse(response)
                .badRequest()
                .hasError('INVALID_FILE_TYPE');
        });
    });

    // ============================================================================
    // Rate Limiting Tests
    // ============================================================================

    describe('Rate Limiting', () => {
        it('should rate limit excessive requests', async () => {
            const requests = Array(100)
                .fill()
                .map(() => client.get('/api/health'));

            const responses = await Promise.all(requests);
            const rateLimited = responses.filter((r) => r.status === 429);

            expect(rateLimited.length).toBeGreaterThan(0);
        });
    });

    // ============================================================================
    // Concurrent Operations Tests
    // ============================================================================

    describe('Concurrent Operations', () => {
        it('should handle concurrent updates correctly', async () => {
            const user = await createUser(prisma);
            const post = await createPost(prisma, user.id, { viewCount: 0 });
            const token = createAuthToken(user.id);

            // Simulate 10 concurrent view increments
            const requests = Array(10)
                .fill()
                .map(() => client.authPost(`/api/posts/${post.id}/view`, {}, token));

            await Promise.all(requests);

            const updated = await prisma.post.findUnique({ where: { id: post.id } });
            expect(updated.viewCount).toBe(10);
        });
    });
});
