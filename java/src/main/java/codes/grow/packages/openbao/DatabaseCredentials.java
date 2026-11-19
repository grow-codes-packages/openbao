package codes.grow.packages.openbao;

import codes.grow.packages.openbao.core.Secret;

/**
 * Dynamic database credentials ({@code GET database/creds/<role>}).
 *
 * @param username generated user name
 * @param password generated password (redacted)
 */
public record DatabaseCredentials(String username, Secret password) {}
