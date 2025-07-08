/**
 * Extracts the user name part from a user name that may include a domain.
 * @param userName - A user name that may include a domain, e.g., "domain\user" or "user".
 * @returns The user name part extracted from the provided user name.
 */
export function getUserNamePart(userName) {
    // Extract the user name part from a user name that may include a domain.
    const parts = userName.split('\\');
    const userNamePart = parts.length === 2 ? parts[1] : parts[0];
    return userNamePart;
}
