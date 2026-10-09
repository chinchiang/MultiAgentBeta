// Unmount what each test rendered: testing-library cleans up by itself only with global test hooks.
import { cleanup } from '@testing-library/react';
import { afterEach } from 'vitest';

afterEach(cleanup);
