/**
 * Extracts the user name part from a user name that may include a domain.
 * @param username - A user name that may include a domain, e.g., "domain\user" or "user".
 * @returns The user name part extracted from the provided user name.
 */
export function getUsernamePart(username) {
    if (username.includes('@')) {
        // If the user name includes an '@', split by '@' and return the first part.
        const parts = username.split('@');
        return parts[0];
    }
    // Extract the user name part from a user name that may include a domain.
    const parts = username.split('\\');
    const usernamePart = parts.length === 2 ? parts[1] : parts[0];
    return usernamePart;
}
