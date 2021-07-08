package org.apache.sshd.server.config.keys;

import org.apache.sshd.common.config.keys.AuthorizedKeyEntry;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.server.auth.pubkey.PublickeyAuthenticator;
import org.apache.sshd.server.auth.pubkey.RejectAllPublickeyAuthenticator;
import org.apache.sshd.server.session.ServerSession;

import java.io.IOException;
import java.io.StreamCorruptedException;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

/**
 * 基于DB的公钥身份认证器框架，只需自行实现queryPubKeyStringList方法即可
 * @author xiejiajun
 */
public class JdbcAuthorizedKeysAuthenticator extends AuthorizedKeysAuthenticator {
    public JdbcAuthorizedKeysAuthenticator(Path file) {
        super(file);
    }

    public JdbcAuthorizedKeysAuthenticator(Path file, LinkOption... options) {
        super(file, options);
    }

    @Override
    protected boolean isValidUsername(String username, ServerSession session) {
        // TODO 基于JDBC的密钥管理器只需要username不为空就支持公钥认证(父类的默认策略)，
        //  因为拉取认证时的pubkey列表时会以username作为查询条件去拉取只属于username
        //  工作空间的pubkey列表，这跟Linux的免密登陆行为可以对标，Linux用哪个用户登陆就是
        //  就读取哪个用户的home目录下的.ssh/authorized_keys文件拉取公钥列表进行挨个匹配
        return super.isValidUsername(username, session);
    }

    @Override
    protected PublickeyAuthenticator resolvePublickeyAuthenticator(String username, ServerSession session)
            throws IOException, GeneralSecurityException {
        Collection<AuthorizedKeyEntry> entries = this.reloadAuthorizedKeys(null, username, session);
        if (GenericUtils.size(entries) > 0) {
            // TODO AuthorizedKeyEntriesPublickeyAuthenticator / RejectAllPublickeyAuthenticator
            return PublickeyAuthenticator.fromAuthorizedEntries("jdbcAuthenticator", session, entries, getFallbackPublicKeyEntryResolver());
        }
        return RejectAllPublickeyAuthenticator.INSTANCE;
    }

    @Override
    protected Collection<AuthorizedKeyEntry> reloadAuthorizedKeys(
            Path path, String username, ServerSession session)
            throws IOException, GeneralSecurityException {

        // TODO 以username为查询条件从数据库里面读取pubKey列表，不为空则直接返回，为空则走父类的从authorized_keys文件解析的逻辑
        Collection<AuthorizedKeyEntry> entries = this.reloadAuthorizedKeysFromDb(username);
        if (GenericUtils.size(entries) > 0) {
            log.info("reloadAuthorizedKeys({})[{}] loaded {} keys from db",
                    username, session, GenericUtils.size(entries));
            this.updateReloadAttributes();
            return entries;
        }
        return Collections.emptyList();
    }

    /**
     * 当前系统用户，目前用不上
     * @param username
     * @return
     * @throws IOException
     */
    private Collection<AuthorizedKeyEntry> reloadAuthorizedKeysFromDb(String username) throws IOException {
        // TODO 以username为查询条件从数据库里面读取pubKey字符串列表，并转换成AuthorizedKeyEntry列表
        //  根据pubKey String构建AuthorizedKeyEntry对象的逻辑参考AuthorizedKeyEntry.readAuthorizedKeys(path)
        //  -> ... -> AuthorizedKeyEntry.parseAuthorizedKeyEntry(String, PublicKeyEntryDataResolver)
        Collection<String> pubKeyList = this.queryPubKeyStringList(username);
        if (GenericUtils.size(pubKeyList) <= 0) {
            return Collections.emptyList();
        }
        // TODO 将pubKeyList转换成AuthorizedKeyEntry列表
        List<AuthorizedKeyEntry> entries = null;
        for (String line : pubKeyList) {
            AuthorizedKeyEntry entry;
            try {
                entry = AuthorizedKeyEntry.parseAuthorizedKeyEntry(line);
                if (entry == null) {
                    continue; // null, empty or comment line
                }
            } catch (RuntimeException | Error e) {
                throw new StreamCorruptedException(
                        "Failed (" + e.getClass().getSimpleName() + ")"
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
    private List<String> queryPubKeyStringList(String username) {
        return new ArrayList<>();
    }
}
