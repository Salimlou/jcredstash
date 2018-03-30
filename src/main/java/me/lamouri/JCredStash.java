package me.lamouri;

import com.amazonaws.auth.AWSCredentialsProvider;
import com.amazonaws.regions.Regions;
import com.amazonaws.services.dynamodbv2.AmazonDynamoDB;
import com.amazonaws.services.dynamodbv2.AmazonDynamoDBClientBuilder;
import com.amazonaws.services.dynamodbv2.model.AttributeValue;
import com.amazonaws.services.dynamodbv2.model.ComparisonOperator;
import com.amazonaws.services.dynamodbv2.model.Condition;
import com.amazonaws.services.dynamodbv2.model.GetItemRequest;
import com.amazonaws.services.dynamodbv2.model.GetItemResult;
import com.amazonaws.services.dynamodbv2.model.PutItemRequest;
import com.amazonaws.services.dynamodbv2.model.QueryRequest;
import com.amazonaws.services.dynamodbv2.model.QueryResult;
import com.amazonaws.services.dynamodbv2.model.ScanRequest;
import com.amazonaws.services.dynamodbv2.model.ScanResult;
import com.amazonaws.services.kms.AWSKMS;
import com.amazonaws.services.kms.AWSKMSClientBuilder;
import com.amazonaws.services.kms.model.DecryptRequest;
import com.amazonaws.services.kms.model.DecryptResult;
import com.amazonaws.services.kms.model.GenerateDataKeyRequest;
import com.amazonaws.services.kms.model.GenerateDataKeyResult;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;

import java.io.UnsupportedEncodingException;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.NoSuchElementException;

/**
 * Created by jcoyle on 2/1/16.
 */
public class JCredStash {
    protected AmazonDynamoDB amazonDynamoDBClient;
    protected AWSKMS awskmsClient;
    protected CredStashCrypto cryptoImpl;

    public JCredStash() {
        this.amazonDynamoDBClient = AmazonDynamoDBClientBuilder.defaultClient();
        this.awskmsClient = AWSKMSClientBuilder.defaultClient();
        this.cryptoImpl = new CredStashBouncyCastleCrypto();
    }

    public JCredStash(Regions region) {
        this.amazonDynamoDBClient = AmazonDynamoDBClientBuilder.standard().withRegion(region).build();
        this.awskmsClient = AWSKMSClientBuilder.standard().withRegion(region).build();
        this.cryptoImpl = new CredStashBouncyCastleCrypto();
    }

    public JCredStash(AWSCredentialsProvider awsCredentialsProvider) {
        this.amazonDynamoDBClient = AmazonDynamoDBClientBuilder.standard().withCredentials(awsCredentialsProvider).build();
        this.awskmsClient = AWSKMSClientBuilder.standard().withCredentials(awsCredentialsProvider).build();
        this.cryptoImpl = new CredStashBouncyCastleCrypto();
    }

    public JCredStash(AWSCredentialsProvider awsCredentialsProvider, Regions region) {
        this.amazonDynamoDBClient = AmazonDynamoDBClientBuilder.standard().withCredentials(awsCredentialsProvider).withRegion(region).build();
        this.awskmsClient = AWSKMSClientBuilder.standard().withCredentials(awsCredentialsProvider).withRegion(region).build();
        this.cryptoImpl = new CredStashBouncyCastleCrypto();
    }

    public JCredStash(AmazonDynamoDB amazonDynamoDBClient, AWSKMS awskmsClient) {
        this.amazonDynamoDBClient = amazonDynamoDBClient;
        this.awskmsClient = awskmsClient;
        this.cryptoImpl = new CredStashBouncyCastleCrypto();
    }

    /**
     * Represents a row in a credstash table. The encrypted key and encrypted contents are both stored base64 encoded.
     * The hmac digest is stored hex encoded.
     */
    protected static class StoredSecret {
        protected Map<String, AttributeValue> item;

        protected static byte[] base64AttributeValueToBytes(AttributeValue value) {
            return Base64.getDecoder().decode(value.getS());
        }

        protected static byte[] hexAttributeValueToBytes(AttributeValue value) {
            // Refactored to support latest CredStash versions
            // https://github.com/jessecoyle/jcredstash/pull/8/files
            ByteBuffer b = value.getB();
            byte[] attr;

            try {
                if (b.remaining() > 0) {
                    // support for current versions of credstash
                    attr = value.getB().array();
                } else {
                    // support for backwards compatibility
                    attr = value.getS().getBytes("UTF-8");
                }
            } catch (UnsupportedEncodingException e) {
                throw new RuntimeException(e);
            }

            Hex hexDecoder = new Hex("UTF-8");
            try {
                return hexDecoder.decode(attr);
            } catch (DecoderException e) {
                throw new RuntimeException(e);
            }
        }

        public StoredSecret(Map<String, AttributeValue> item) {
            this.item = item;
        }

        public byte[] getKey() {
            return base64AttributeValueToBytes(item.get("key"));
        }

        public byte[] getContents() {
            return base64AttributeValueToBytes(item.get("contents"));
        }

        public byte[] getHmac() {
            return hexAttributeValueToBytes(item.get("hmac"));
        }

        public String getVersion() {
            return item.get("version").getS();
        }

        public String getName() {
            return item.get("name").getS();
        }
    }

    protected QueryRequest basicQueryRequest(String tableName, String secretName) {
        return new QueryRequest(tableName)
                .withLimit(1)
                .withScanIndexForward(false)
                .withConsistentRead(true)
                .addKeyConditionsEntry("name", new Condition()
                        .withComparisonOperator(ComparisonOperator.EQ)
                        .withAttributeValueList(new AttributeValue(secretName)));
    }

    /**
     * Get the highest version of a secret.
     *
     * @param tableName  Credstash DynamoDB table name
     * @param secretName Credstash secret name
     * @return The highest version of the secret or null if no secret with that name exists
     */
    public String getHighestVersion(String tableName, String secretName) {
        QueryResult queryResult = amazonDynamoDBClient.query(
                basicQueryRequest(tableName, secretName)
                        .withProjectionExpression("version")
        );
        if (queryResult.getCount() == 0) {
            return null;
        }
        Map<String, AttributeValue> item = queryResult.getItems().get(0);

        return new StoredSecret(item).getVersion();
    }

    protected StoredSecret readVersionedDynamoItem(String tableName, String secretName, String version) {
        HashMap<String, AttributeValue> key = new HashMap<>();
        key.put("name", new AttributeValue(secretName));
        key.put("version", new AttributeValue(version));
        GetItemResult getItemResult = amazonDynamoDBClient.getItem(new GetItemRequest(tableName, key, true));
        if (getItemResult == null) {
            return null;
        }
        Map<String, AttributeValue> item = getItemResult.getItem();

        return new StoredSecret(item);
    }

    protected StoredSecret readHighestVersionDynamoItem(String tableName, String secretName) {
        QueryResult queryResult = amazonDynamoDBClient.query(
                basicQueryRequest(tableName, secretName)
        );
        if (queryResult.getCount() == 0) {
            return null;
        }
        Map<String, AttributeValue> item = queryResult.getItems().get(0);

        return new StoredSecret(item);
    }

    /**
     * Iterator containing the complexity of paging through a scan. This allows calling code to be responsive
     * as paged results are retrieved.
     */
    protected class ListItemIterator implements Iterator<StoredSecret> {
        protected final ScanRequest scanRequest;
        protected ScanResult scanResult = null;
        protected Iterator<Map<String, AttributeValue>> scanIterator = null;

        public ListItemIterator(String tableName, String secretPrefix) {
            this.scanRequest = new ScanRequest(tableName)
                    .withProjectionExpression("#N, version");

            this.scanRequest.addExpressionAttributeNamesEntry("#N", "name");

            if (secretPrefix != null) {
                this.scanRequest.addExpressionAttributeValuesEntry(":secretPrefix", new AttributeValue(secretPrefix));
                this.scanRequest.setFilterExpression("begins_with(#N, :secretPrefix)");
            }

            nextPage();
        }

        protected void nextPage() {
            ScanRequest request = this.scanRequest.withExclusiveStartKey(scanResult == null ? null : scanResult.getLastEvaluatedKey());
            scanResult = amazonDynamoDBClient.scan(request);
            if (scanResult.getCount() == 0) {
                scanResult = null;
                scanIterator = null;
            } else {
                scanIterator = scanResult.getItems().iterator();
            }
        }

        @Override
        public boolean hasNext() {
            if (scanIterator == null) {
                return false;
            }
            if (scanIterator.hasNext()) {
                return true;
            }
            if (scanResult == null || scanResult.getLastEvaluatedKey() == null) {
                return false;
            }
            nextPage();
            return hasNext();
        }

        @Override
        public StoredSecret next() {
            if (!hasNext()) {
                throw new NoSuchElementException();
            }
            return new StoredSecret(scanIterator.next());
        }
    }

    protected Iterator<StoredSecret> listDynamoItem(String tableName, String secretPrefix) {
        return new ListItemIterator(tableName, secretPrefix);
    }

    /**
     * Retrieve a set of secrets all at once. Most useful if secrets are named with paths for grouping
     *
     * @param tableName    the dynamo table name (likely "credential-store")
     * @param secretPrefix the prefix for all secrets to get
     * @param context      encryption context key/value pairs associated with the credential in the form of "key=value"
     * @return Map of all secrets found
     */
    public Map<String, String> getAllSecrets(String tableName, String secretPrefix, Map<String, String> context) {
        Iterator<StoredSecret> iter = listDynamoItem(tableName, secretPrefix);
        Map<String, String> latestVersions = new HashMap<>();
        while (iter.hasNext()) {
            StoredSecret next = iter.next();
            String name = next.getName();
            String version = next.getVersion();
            if (!latestVersions.containsKey(name) || latestVersions.get(name).compareTo(version) < 0) {
                latestVersions.put(name, version);
            }
        }
        Map<String, String> results = new HashMap<>();
        for (Map.Entry<String, String> entry : latestVersions.entrySet()) {
            String secret = getSecret(tableName, entry.getKey(), context, entry.getValue());
            results.put(entry.getKey(), secret);
        }
        return results;
    }

    protected ByteBuffer decryptKeyWithKMS(byte[] encryptedKeyBytes, Map<String, String> context) {
        // Refactored to support latest CredStash versions
        // https://github.com/jessecoyle/jcredstash/pull/8/files
        ByteBuffer blob = ByteBuffer.wrap(encryptedKeyBytes);
        DecryptRequest decryptRequest = new DecryptRequest().withCiphertextBlob(blob);

        if(context != null) {
            decryptRequest.withEncryptionContext(context);
        }
        DecryptResult decryptResult = awskmsClient.decrypt(decryptRequest);

        return decryptResult.getPlaintext();
    }

    /**
     * Gets a secret from credstash.
     *
     * @param tableName  the dynamo table name (likely "credential-store")
     * @param secretName the name of the secret to get
     * @return unencrypted secret
     */
    public String getSecret(String tableName, String secretName) {
        return getSecret(tableName, secretName, Collections.emptyMap(), null);
    }

    /**
     * Gets a secret from credstash.
     *
     * @param tableName  the dynamo table name (likely "credential-store")
     * @param secretName the name of the secret to get
     * @param context    encryption context key/value pairs associated with the credential in the form of "key=value"
     * @return unencrypted secret
     */
    public String getSecret(String tableName, String secretName, Map<String, String> context) {
        return getSecret(tableName, secretName, context, null);
    }

    /**
     * Gets a secret from credstash with a specified version
     *
     * @param tableName  the dynamo table name (likely "credential-store")
     * @param secretName the name of the secret to get
     * @param context    encryption context key/value pairs associated with the credential in the form of "key=value"
     * @param version    a particular version string to lookup (null for latest version)
     * @return unencrypted secret
     */
    public String getSecret(String tableName, String secretName, Map<String, String> context, String version) {
        // First find the relevant rows from the credstash table
        StoredSecret encrypted = version == null ? readHighestVersionDynamoItem(tableName, secretName) : readVersionedDynamoItem(tableName, secretName, version);
        if (encrypted == null) {
            throw new RuntimeException("Secret " + secretName + " could not be found");
        }
        return getSecret(encrypted, context);
    }

    protected String getSecret(StoredSecret encrypted, Map<String, String> context) {

        // The secret was encrypted using AES, then the key for that encryption was encrypted with AWS KMS
        // Then both the encrypted secret and the encrypted key are stored in dynamo

        // First obtain that original key again using KMS
        ByteBuffer plainText = decryptKeyWithKMS(encrypted.getKey(), context);

        // The key is just the first 32 bits, the remaining are for HMAC signature checking
        byte[] keyBytes = new byte[32];
        plainText.get(keyBytes);

        byte[] hmacKeyBytes = new byte[plainText.remaining()];
        plainText.get(hmacKeyBytes);
        byte[] encryptedContents = encrypted.getContents();
        byte[] digest = cryptoImpl.digest(hmacKeyBytes, encryptedContents);
        if (!Arrays.equals(digest, encrypted.getHmac())) {
            throw new RuntimeException("HMAC integrity check failed"); //TODO custom exception type
        }

        // now use AES to finally decrypt the actual secret
        byte[] decryptedBytes = cryptoImpl.decrypt(keyBytes, encryptedContents);
        return new String(decryptedBytes);
    }

    /**
     * Puts a secret into credstash with auto-versioning. Uses a 19 character padded integer as a version and
     * will auto-increment each time a secret is stashed.
     *
     * @param tableName  Credstash DynamoDB table name
     * @param secretName Credstash secret name
     * @param secret     The secret value
     * @param kmsKeyId   The KMS KeyId used to generate a new data key
     * @param context    Encryption context for integrity check
     * @throws NumberFormatException If the currently stashed secrets highest version can't be parsed to an integer
     */
    public void putSecret(String tableName, String secretName, String secret, String kmsKeyId, Map<String, String> context) {
        String version = getHighestVersion(tableName, secretName);
        if (version != null) {
            int v = Integer.parseInt(version);
            version = padVersion(v + 1);
        }
        putSecret(tableName, secretName, secret, kmsKeyId, context, version);
    }

    /**
     * Puts a secret into credstash with a specified version.
     *
     * @param tableName  Credstash DynamoDB table name
     * @param secretName Credstash secret name
     * @param secret     The secret value
     * @param kmsKeyId   The KMS KeyId used to generate a new data key
     * @param context    Encryption context for integrity check
     * @param version    An optional version string to be used when stashing the secret, defaults to '1' (padded)
     * @throws com.amazonaws.services.dynamodbv2.model.ConditionalCheckFailedException If the version already exists.
     */
    public void putSecret(String tableName, String secretName, String secret, String kmsKeyId, Map<String, String> context, String version) {

        String newVersion = version;
        if (newVersion == null) {
            newVersion = padVersion(1);
        }

        GenerateDataKeyRequest dataKeyRequest = new GenerateDataKeyRequest().withKeyId(kmsKeyId).withNumberOfBytes(64);

        if (context != null) {
            dataKeyRequest.withEncryptionContext(context);
        }

        GenerateDataKeyResult generateDataKeyResult = awskmsClient.generateDataKey(dataKeyRequest);
        ByteBuffer plainTextKey = generateDataKeyResult.getPlaintext();
        ByteBuffer cipherTextBlob = generateDataKeyResult.getCiphertextBlob();

        byte[] keyBytes = new byte[32];
        plainTextKey.get(keyBytes);

        byte[] hmacKeyBytes = new byte[plainTextKey.remaining()];
        plainTextKey.get(hmacKeyBytes);

        byte[] encryptedKeyBytes = new byte[cipherTextBlob.remaining()];
        cipherTextBlob.get(encryptedKeyBytes);

        byte[] contents = cryptoImpl.encrypt(keyBytes, secret.getBytes());
        byte[] hmac = cryptoImpl.digest(hmacKeyBytes, contents);

        Map<String, AttributeValue> item = new HashMap<>();
        item.put("name", new AttributeValue(secretName));
        item.put("version", new AttributeValue(newVersion));
        item.put("key", new AttributeValue(new String(Base64.getEncoder().encode(encryptedKeyBytes))));
        item.put("contents", new AttributeValue(new String(Base64.getEncoder().encode(contents))));
        try {
            // Refactored to support latest CredStash versions
            // https://github.com/jessecoyle/jcredstash/pull/8/files
            item.put("hmac", new AttributeValue().withB(ByteBuffer.wrap(Hex.encodeHexString(hmac).getBytes("UTF-8"))));
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException(e);
        }

        Map<String, String> expressionAttributes = new HashMap<>();
        expressionAttributes.put("#N", "name");

        amazonDynamoDBClient.putItem(new PutItemRequest(tableName, item)
                .withConditionExpression("attribute_not_exists(#N)")
                .withExpressionAttributeNames(expressionAttributes));
    }

    private String padVersion(int version) {
        return String.format("%019d", version);
    }
}