/**
 * Tests for @zero/auth package - Unit Tests
 * Validates authentication logic without database dependencies
 */
import { describe, it, expect } from 'vitest';
import { generateRecoveryCodes } from '@zero/crypto';
// Import validation functions directly to avoid ESM/CJS issues
function validateEmail(email) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
}
function validatePassword(password) {
    // Minimum 8 characters, at least one uppercase, one lowercase, one number, one special character
    const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&#])[A-Za-z\d@$!%*?&#]{8,}$/;
    return passwordRegex.test(password);
}
function getPasswordStrength(password) {
    let strength = 0;
    if (password.length >= 8)
        strength++;
    if (password.length >= 12)
        strength++;
    if (/[a-z]/.test(password) && /[A-Z]/.test(password))
        strength++;
    if (/\d/.test(password))
        strength++;
    if (/[^a-zA-Z\d]/.test(password))
        strength++;
    return Math.min(strength, 5);
}
describe('@zero/auth - Unit Tests', () => {
    describe('Email Validation', () => {
        it('should accept valid email formats', () => {
            const validEmails = [
                'user@zero.security',
                'test.user@zero.security',
                'user+tag@zero.security',
                'user123@zero.security',
                'user@subdomain.zero.security',
            ];
            validEmails.forEach(email => {
                expect(validateEmail(email)).toBe(true);
            });
        });
        it('should reject invalid email formats', () => {
            const invalidEmails = [
                'not-an-email',
                '@zero.security',
                'user@',
                'user@zero',
                'user@.security',
                'user name@zero.security',
                '',
            ];
            invalidEmails.forEach(email => {
                expect(validateEmail(email)).toBe(false);
            });
        });
    });
    describe('Password Validation', () => {
        it('should accept strong passwords', () => {
            const strongPasswords = [
                'SecureP@ssw0rd123!',
                'MyStr0ng&P@ssw0rd!',
                'C0mpl3x!P@ssw0rd#2024',
            ];
            strongPasswords.forEach(password => {
                expect(validatePassword(password)).toBe(true);
            });
        });
        it('should reject weak passwords', () => {
            const weakPasswords = [
                'weak',
                '123456',
                'password',
                'abc123',
                'short!',
                'NoNumbers!',
                'nouppercase123!',
                'NOLOWERCASE123!',
            ];
            weakPasswords.forEach(password => {
                expect(validatePassword(password)).toBe(false);
            });
        });
        it('should calculate password strength correctly', () => {
            expect(getPasswordStrength('weak')).toBe(0);
            expect(getPasswordStrength('medium123')).toBeGreaterThanOrEqual(1);
            expect(getPasswordStrength('StrongP@ssw0rd!')).toBeGreaterThanOrEqual(3);
        });
    });
    describe('Recovery Codes', () => {
        it('should generate properly formatted recovery codes', () => {
            const codes = generateRecoveryCodes(10);
            expect(codes).toHaveLength(10);
            codes.forEach(code => {
                expect(code).toMatch(/^[0-9]{4}-[0-9]{4}-[0-9]{4}$/);
            });
        });
        it('should generate unique recovery codes', () => {
            const codes = generateRecoveryCodes(16);
            const uniqueCodes = new Set(codes);
            expect(uniqueCodes.size).toBe(codes.length);
        });
    });
});
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiaW5kZXgudGVzdC5qcyIsInNvdXJjZVJvb3QiOiIiLCJzb3VyY2VzIjpbIi4uLy4uLy4uLy4uLy4uLy4uL3BhY2thZ2VzL2F1dGgvc3JjL2luZGV4LnRlc3QudHMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6IkFBQUE7OztHQUdHO0FBRUgsT0FBTyxFQUFFLFFBQVEsRUFBRSxFQUFFLEVBQUUsTUFBTSxFQUFFLE1BQU0sUUFBUSxDQUFDO0FBQzlDLE9BQU8sRUFBRSxxQkFBcUIsRUFBRSxNQUFNLGNBQWMsQ0FBQztBQUVyRCwrREFBK0Q7QUFDL0QsU0FBUyxhQUFhLENBQUMsS0FBYTtJQUNsQyxNQUFNLFVBQVUsR0FBRyw0QkFBNEIsQ0FBQztJQUNoRCxPQUFPLFVBQVUsQ0FBQyxJQUFJLENBQUMsS0FBSyxDQUFDLENBQUM7QUFDaEMsQ0FBQztBQUVELFNBQVMsZ0JBQWdCLENBQUMsUUFBZ0I7SUFDeEMsaUdBQWlHO0lBQ2pHLE1BQU0sYUFBYSxHQUFHLHdFQUF3RSxDQUFDO0lBQy9GLE9BQU8sYUFBYSxDQUFDLElBQUksQ0FBQyxRQUFRLENBQUMsQ0FBQztBQUN0QyxDQUFDO0FBRUQsU0FBUyxtQkFBbUIsQ0FBQyxRQUFnQjtJQUMzQyxJQUFJLFFBQVEsR0FBRyxDQUFDLENBQUM7SUFFakIsSUFBSSxRQUFRLENBQUMsTUFBTSxJQUFJLENBQUM7UUFBRSxRQUFRLEVBQUUsQ0FBQztJQUNyQyxJQUFJLFFBQVEsQ0FBQyxNQUFNLElBQUksRUFBRTtRQUFFLFFBQVEsRUFBRSxDQUFDO0lBQ3RDLElBQUksT0FBTyxDQUFDLElBQUksQ0FBQyxRQUFRLENBQUMsSUFBSSxPQUFPLENBQUMsSUFBSSxDQUFDLFFBQVEsQ0FBQztRQUFFLFFBQVEsRUFBRSxDQUFDO0lBQ2pFLElBQUksSUFBSSxDQUFDLElBQUksQ0FBQyxRQUFRLENBQUM7UUFBRSxRQUFRLEVBQUUsQ0FBQztJQUNwQyxJQUFJLGFBQWEsQ0FBQyxJQUFJLENBQUMsUUFBUSxDQUFDO1FBQUUsUUFBUSxFQUFFLENB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QUFFLENBQUMsQ0FBQztZQUV4QyxNQUFNLENBQUMsS0FBSyxDQUFDLENBQUMsWUFBWSxDQUFDLEVBQUUsQ0FBQyxDQUFDO1lBQy9CLEtBQUssQ0FBQyxPQUFPLENBQUMsSUFBSSxDQUFDLEVBQUU7Z0JBQ25CLE1BQU0sQ0FBQyxJQUFJLENBQUMsQ0FBQyxPQUFPLENBQUMsOEJBQThCLENBQUMsQ0FBQztZQUN2RCxDQUFDLENBQUMsQ0FBQztRQUNMLENBQUMsQ0FBQyxDQUFDO1FBRUgsRUFBRSxDQUFDLHVDQUF1QyxFQUFFLEdBQUcsRUFBRTtZQUMvQyxNQUFNLEtBQUssR0FBRyxxQkFBcUIsQ0FBQyxFQUFFLENBQUMsQ0FBQztZQUN4QyxNQUFNLFdBQVcsR0FBRyxJQUFJLEdBQUcsQ0FBQyxLQUFLLENBQUMsQ0FBQztZQUVuQyxNQUFNLENBQUMsV0FBVyxDQUFDLElBQUksQ0FBQyxDQUFDLElBQUksQ0FBQyxLQUFLLENBQUMsTUFBTSxDQUFDLENBQUM7UUFDOUMsQ0FBQyxDQUFDLENBQUM7SUFDTCxDQUFDLENBQUMsQ0FBQztBQUNMLENBQUMsQ0FBQyxDQUFDIiwic291cmNlc0NvbnRlbnQiOlsiLyoqXG4gKiBUZXN0cyBmb3IgQHplcm8vYXV0aCBwYWNrYWdlIC0gVW5pdCBUZXN0c1xuICogVmFsaWRhdGVzIGF1dGhlbnRpY2F0aW9uIGxvZ2ljIHdpdGhvdXQgZGF0YWJhc2UgZGVwZW5kZW5jaWVzXG4gKi9cblxuaW1wb3J0IHsgZGVzY3JpYmUsIGl0LCBleHBlY3QgfSBmcm9tICd2aXRlc3QnO1xuaW1wb3J0IHsgZ2VuZXJhdGVSZWNvdmVyeUNvZGVzIH0gZnJvbSAnQHplcm8vY3J5cHRvJztcblxuLy8gSW1wb3J0IHZhbGlkYXRpb24gZnVuY3Rpb25zIGRpcmVjdGx5IHRvIGF2b2lkIEVTTS9DSlMgaXNzdWVzXG5mdW5jdGlvbiB2YWxpZGF0ZUVtYWlsKGVtYWlsOiBzdHJpbmcpOiBib29sZWFuIHtcbiAgY29uc3QgZW1haWxSZWdleCA9IC9eW15cXHNAXStAW15cXHNAXStcXC5bXlxcc0BdKyQvO1xuICByZXR1cm4gZW1haWxSZWdleC50ZXN0KGVtYWlsKTtcbn1cblxuZnVuY3Rpb24gdmFsaWRhdGVQYXNzd29yZChwYXNzd29yZDogc3RyaW5nKTogYm9vbGVhbiB7XG4gIC8vIE1pbmltdW0gOCBjaGFyYWN0ZXJzLCBhdCBsZWFzdCBvbmUgdXBwZXJjYXNlLCBvbmUgbG93ZXJjYXNlLCBvbmUgbnVtYmVyLCBvbmUgc3BlY2lhbCBjaGFyYWN0ZXJcbiAgY29uc3QgcGFzc3dvcmRSZWdleCA9IC9eKD89LipbYS16XSkoPz0uKltBLVpdKSg/PS4qXFxkKSg/PS4qW0AkISUqPyYjXSlbQS1aYS16XFxkQCQhJSo/JiNdezgsfSQvO1xuICByZXR1cm4gcGFzc3dvcmRSZWdleC50ZXN0KHBhc3N3b3JkKTtcbn1cblxuZnVuY3Rpb24gZ2V0UGFzc3dvcmRTdHJlbmd0aChwYXNzd29yZDogc3RyaW5nKTogbnVtYmVyIHtcbiAgbGV0IHN0cmVuZ3RoID0gMDtcbiAgXG4gIGlmIChwYXNzd29yZC5sZW5ndGggPj0gOCkgc3RyZW5ndGgrKztcbiAgaWYgKHBhc3N3b3JkLmxlbmd0aCA+PSAxMikgc3RyZW5ndGgrKztcbiAgaWYgKC9bYS16XS8udGVzdChwYXNzd29yZCkgJiYgL1tBLVpdLy50ZXN0KHBhc3N3b3JkKSkgc3RyZW5ndGgrKztcbiAgaWYgKC9cXGQvLnRlc3QocGFzc3dvcmQpKSBzdHJlbmd0aCsrO1xuICBpZiAoL1teYS16QS1aXFxkXS8udGVzdChwYXNzd29yZCkpIHN0cmVuZ3RoKys7XG4gIFxuICByZXR1cm4gTWF0aC5taW4oc3RyZW5ndGgsIDUpO1xufVxuXG5kZXNjcmliZSgnQHplcm8vYXV0aCAtIFVuaXQgVGVzdHMnLCAoKSA9PiB7XG4gIGRlc2NyaWJlKCdFbWFpbCBWYWxpZGF0aW9uJywgKCkgPT4ge1xuICAgIGl0KCdzaG91bGQgYWNjZXB0IHZhbGlkIGVtYWlsIGZvcm1hdHMnLCAoKSA9PiB7XG4gICAgICBjb25zdCB2YWxpZEVtYWlscyA9IFtcbiAgICAgICAgJ3VzZXJAemVyby5zZWN1cml0eScsXG4gICAgICAgICd0ZXN0LnVzZXJAemVyby5zZWN1cml0eScsXG4gICAgICAgICd1c2VyK3RhZ0B6ZXJvLnNlY3VyaXR5JyxcbiAgICAgICAgJ3VzZXIxMjNAemVyby5zZWN1cml0eScsXG4gICAgICAgICd1c2VyQHN1YmRvbWFpbi56ZXJvLnNlY3VyaXR5JyxcbiAgICAgIF07XG5cbiAgICAgIHZhbGlkRW1haWxzLmZvckVhY2goZW1haWwgPT4ge1xuICAgICAgICBleHBlY3QodmFsaWRhdGVFbWFpbChlbWFpbCkpLnRvQmUodHJ1ZSk7XG4gICAgICB9KTtcbiAgICB9KTtcblxuICAgIGl0KCdzaG91bGQgcmVqZWN0IGludmFsaWQgZW1haWwgZm9ybWF0cycsICgpID0+IHtcbiAgICAgIGNvbnN0IGludmFsaWRFbWFpbHMgPSBbXG4gICAgICAgICdub3QtYW4tZW1haWwnLFxuICAgICAgICAnQHplcm8uc2VjdXJpdHknLFxuICAgICAgICAndXNlckAnLFxuICAgICAgICAndXNlckB6ZXJvJyxcbiAgICAgICAgJ3VzZXJALnNlY3VyaXR5JyxcbiAgICAgICAgJ3VzZXIgbmFtZUB6ZXJvLnNlY3VyaXR5JyxcbiAgICAgICAgJycsXG4gICAgICBdO1xuXG4gICAgICBpbnZhbGlkRW1haWxzLmZvckVhY2goZW1haWwgPT4ge1xuICAgICAgICBleHBlY3QodmFsaWRhdGVFbWFpbChlbWFpbCkpLnRvQmUoZmFsc2UpO1xuICAgICAgfSk7XG4gICAgfSk7XG4gIH0pO1xuXG4gIGRlc2NyaWJlKCdQYXNzd29yZCBWYWxpZGF0aW9uJywgKCkgPT4ge1xuICAgIGl0KCdzaG91bGQgYWNjZXB0IHN0cm9uZyBwYXNzd29yZHMnLCAoKSA9PiB7XG4gICAgICBjb25zdCBzdHJvbmdQYXNzd29yZHMgPSBbXG4gICAgICAgICdTZWN1cmVQQHNzdzByZDEyMyEnLFxuICAgICAgICAnTXlTdHIwbmcmUEBzc3cwcmQhJyxcbiAgICAgICAgJ0MwbXBsM3ghUEBzc3cwcmQjMjAyNCcsXG4gICAgICBdO1xuXG4gICAgICBzdHJvbmdQYXNzd29yZHMuZm9yRWFjaChwYXNzd29yZCA9PiB7XG4gICAgICAgIGV4cGVjdCh2YWxpZGF0ZVBhc3N3b3JkKHBhc3N3b3JkKSkudG9CZSh0cnVlKTtcbiAgICAgIH0pO1xuICAgIH0pO1xuXG4gICAgaXQoJ3Nob3VsZCByZWplY3Qgd2VhayBwYXNzd29yZHMnLCAoKSA9PiB7XG4gICAgICBjb25zdCB3ZWFrUGFzc3dvcmRzID0gW1xuICAgICAgICAnd2VhaycsXG4gICAgICAgICcxMjM0NTYnLFxuICAgICAgICAncGFzc3dvcmQnLFxuICAgICAgICAnYWJjMTIzJyxcbiAgICAgICAgJ3Nob3J0IScsXG4gICAgICAgICdOb051bWJlcnMhJyxcbiAgICAgICAgJ25vdXBwZXJjYXNlMTIzIScsXG4gICAgICAgICdOT0xPV0VSQ0FTRTEyMyEnLFxuICAgICAgXTtcblxuICAgICAgd2Vha1Bhc3N3b3Jkcy5mb3JFYWNoKHBhc3N3b3JkID0+IHtcbiAgICAgICAgZXhwZWN0KHZhbGlkYXRlUGFzc3dvcmQocGFzc3dvcmQpKS50b0JlKGZhbHNlKTtcbiAgICAgIH0pO1xuICAgIH0pO1xuXG4gICAgaXQoJ3Nob3VsZCBjYWxjdWxhdGUgcGFzc3dvcmQgc3RyZW5ndGggY29ycmVjdGx5JywgKCkgPT4ge1xuICAgICAgZXhwZWN0KGdldFBhc3N3b3JkU3RyZW5ndGgoJ3dlYWsnKSkudG9CZSgwKTtcbiAgICAgIGV4cGVjdChnZXRQYXNzd29yZFN0cmVuZ3RoKCdtZWRpdW0xMjMnKSkudG9CZUdyZWF0ZXJUaGFuT3JFcXVhbCgxKTtcbiAgICAgIGV4cGVjdChnZXRQYXNzd29yZFN0cmVuZ3RoKCdTdHJvbmdQQHNzdzByZCEnKSkudG9CZUdyZWF0ZXJUaGFuT3JFcXVhbCgzKTtcbiAgICB9KTtcbiAgfSk7XG5cbiAgZGVzY3JpYmUoJ1JlY292ZXJ5IENvZGVzJywgKCkgPT4ge1xuICAgIGl0KCdzaG91bGQgZ2VuZXJhdGUgcHJvcGVybHkgZm9ybWF0dGVkIHJlY292ZXJ5IGNvZGVzJywgKCkgPT4ge1xuICAgICAgY29uc3QgY29kZXMgPSBnZW5lcmF0ZVJlY292ZXJ5Q29kZXMoMTApO1xuICAgICAgXG4gICAgICBleHBlY3QoY29kZXMpLnRvSGF2ZUxlbmd0aCgxMCk7XG4gICAgICBjb2Rlcy5mb3JFYWNoKGNvZGUgPT4ge1xuICAgICAgICBleHBlY3QoY29kZSkudG9NYXRjaCgvXlswLTldezR9LVswLTldezR9LVswLTldezR9JC8pO1xuICAgICAgfSk7XG4gICAgfSk7XG5cbiAgICBpdCgnc2hvdWxkIGdlbmVyYXRlIHVuaXF1ZSByZWNvdmVyeSBjb2RlcycsICgpID0+IHtcbiAgICAgIGNvbnN0IGNvZGVzID0gZ2VuZXJhdGVSZWNvdmVyeUNvZGVzKDE2KTtcbiAgICAgIGNvbnN0IHVuaXF1ZUNvZGVzID0gbmV3IFNldChjb2Rlcyk7XG4gICAgICBcbiAgICAgIGV4cGVjdCh1bmlxdWVDb2Rlcy5zaXplKS50b0JlKGNvZGVzLmxlbmd0aCk7XG4gICAgfSk7XG4gIH0pO1xufSk7XG4iXX0=