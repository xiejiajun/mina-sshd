package org.apache.sshd.server.config.keys;

import org.apache.sshd.common.config.keys.AuthorizedKeyEntry;
import org.apache.sshd.common.config.keys.PublicKeyEntryResolver;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.logging.AbstractLoggingBean;
import org.apache.sshd.server.auth.AsyncAuthException;
import org.apache.sshd.server.auth.pubkey.PublickeyAuthenticator;
import org.apache.sshd.server.auth.pubkey.RejectAllPublickeyAuthenticator;
import org.apache.sshd.server.session.ServerSession;

import java.io.IOException;
import java.io.StreamCorruptedException;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.util.*;

/**
 * TODO 和AuthorizedKeysAuthenticator隔离的基于Jdbc的PublicKey认证器，
 *   用户只需自己实现根据username从DB拉取对应的公钥列表的queryPubKeyStringList方法即可
 * @author xiejiajun
 */
public abstract class BaseJdbcAuthorizedKeysAuthenticatorV2 extends AbstractLoggingBean implements PublickeyAuthenticator {

    @Override
    public boolean authenticate(String username, PublicKey key, ServerSession session) throws AsyncAuthException {
        boolean debugEnabled = log.isDebugEnabled();
        if (!isValidUsername(username)) {
            if (debugEnabled) {
                log.debug("authenticate({})[{}][{}] invalid user name", username, session, key.getAlgorithm());
            }
            return false;
        }

        try {
            PublickeyAuthenticator authenticator = this.resolvePublickeyAuthenticator(username, session);
            PublickeyAuthenticator delegate = Objects.requireNonNull(authenticator, "No delegate");
            boolean accepted = delegate.authenticate(username, key, session);
            if (debugEnabled) {
                log.debug("authenticate({})[{}][{}] invalid user name - accepted={} from db", username, session,
                        key.getAlgorithm(), accepted);
            }
            return accepted;
        } catch (Throwable e) {
            log.debug("authenticate({})[{}] failed ({}) to authenticate {} key from db: {}", username, session,
                    e.getClass().getSimpleName(), key.getAlgorithm(), e.getMessage(), e);
            return false;
        }
    }

    /**
     * 检查用户名是否合法
     * @param username
     * @return
     */
    protected boolean isValidUsername(String username) {
        return GenericUtils.isNotEmpty(username);
    }

    /**
     * 构建PubKey校验器
     * @param username
     * @param session
     * @return
     * @throws IOException
     * @throws GeneralSecurityException
     */
    protected PublickeyAuthenticator resolvePublickeyAuthenticator(String username, ServerSession session)
            throws IOException, GeneralSecurityException {
        Collection<AuthorizedKeyEntry> entries = this.reloadAuthorizedKeys(username, session);
        if (GenericUtils.size(entries) > 0) {
            return PublickeyAuthenticator.fromAuthorizedEntries("JdbcAuthenticator", session, entries, PublicKeyEntryResolver.IGNORING);
        }
        return RejectAllPublickeyAuthenticator.INSTANCE;
    }

    /**
     * 加载pubKey列表
     * @param username
     * @param session
     * @return
     * @throws IOException
     */
    protected Collection<AuthorizedKeyEntry> reloadAuthorizedKeys(String username, ServerSession session)
            throws IOException {
        Collection<AuthorizedKeyEntry> entries = this.reloadAuthorizedKeysFromDb(username);
        if (GenericUtils.size(entries) > 0) {
            log.info("reloadAuthorizedKeys({})[{}] loaded {} keys from db", username, session, GenericUtils.size(entries));
            return entries;
        }
        return Collections.emptyList();
    }

    /**
     * @param username
     * @return
     * @throws IOException
     */
    private Collection<AuthorizedKeyEntry> reloadAuthorizedKeysFromDb(String username) throws IOException {
        Collection<String> pubKeyList = this.queryPubKeyStringList(username);
        if (GenericUtils.size(pubKeyList) <= 0) {
            return Collections.emptyList();
        }
        List<AuthorizedKeyEntry> entries = null;
        for (String line : pubKeyList) {
            AuthorizedKeyEntry entry;
            try {
                entry = AuthorizedKeyEntry.parseAuthorizedKeyEntry(line);
                if (entry == null) {
                    continue; // null, empty or comment line
                }
            } catch (RuntimeException | Error e) {
                throw new StreamCorruptedException("Failed (" + e.getClass().getSimpleName() + ")"
                                + " to parse key entry=" + line + ": " + e.getMessage());
            }
            if (entries == null) {
                entries = new ArrayList<>();
            }
            entries.add(entry);
        }

        if (entries == null) {
            return Collections.emptyList();
        }
        return entries;
    }

    /**
     * 以username为查询条件从DB中查询pubkey字符串列表
     * @param username
     * @return
     */
    public abstract List<String> queryPubKeyStringList(String username);

}
