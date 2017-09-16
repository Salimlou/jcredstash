package com.jessecoyle;

import com.amazonaws.services.dynamodbv2.AmazonDynamoDB;
import com.amazonaws.services.dynamodbv2.model.AttributeValue;
import com.amazonaws.services.dynamodbv2.model.GetItemRequest;
import com.amazonaws.services.dynamodbv2.model.GetItemResult;
import com.amazonaws.services.dynamodbv2.model.PutItemRequest;
import com.amazonaws.services.dynamodbv2.model.PutItemResult;
import com.amazonaws.services.dynamodbv2.model.QueryRequest;
import com.amazonaws.services.dynamodbv2.model.QueryResult;
import com.amazonaws.services.kms.AWSKMS;
import com.amazonaws.services.kms.model.DecryptRequest;
import com.amazonaws.services.kms.model.DecryptResult;
import com.amazonaws.services.kms.model.GenerateDataKeyRequest;
import com.amazonaws.services.kms.model.GenerateDataKeyResult;
import org.apache.commons.codec.binary.Hex;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;
import org.mockito.internal.verification.VerificationModeFactory;

import java.nio.ByteBuffer;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

public class JCredStashTest {

    private AmazonDynamoDB dynamoDBClient;
    private AWSKMS awskmsClient;

    @Before
    public void setUp() {
        dynamoDBClient = Mockito.mock(AmazonDynamoDB.class);

        GenerateDataKeyResult generateDatakeyResult = new GenerateDataKeyResult();
        generateDatakeyResult.setCiphertextBlob(Mockito.mock(ByteBuffer.class));
        generateDatakeyResult.setPlaintext(Mockito.mock(ByteBuffer.class));

        DecryptResult decryptResult = new DecryptResult();
        decryptResult.setKeyId("alias/foo");
        decryptResult.setPlaintext(Mockito.mock(ByteBuffer.class));

        awskmsClient = Mockito.mock(AWSKMS.class);
        Mockito.when(awskmsClient.generateDataKey(Mockito.any(GenerateDataKeyRequest.class))).thenReturn(generateDatakeyResult);
        Mockito.when(awskmsClient.decrypt(Mockito.any(DecryptRequest.class))).thenReturn(decryptResult);
    }

    @Test
    public void testPutSecretDefaultVersion() {
        final PutItemRequest[] putItemRequest = new PutItemRequest[1];
        Mockito.when(dynamoDBClient.putItem(Mockito.any(PutItemRequest.class))).thenAnswer(invocationOnMock -> {
            Object[] args = invocationOnMock.getArguments();
            putItemRequest[0] = (PutItemRequest) args[0];
            return new PutItemResult();
        });

        JCredStash credStash = new JCredStash(dynamoDBClient, awskmsClient);
        credStash.putSecret("table", "mysecret", "foo", "alias/foo", new HashMap<>(), null);

        Mockito.verify(dynamoDBClient, VerificationModeFactory.times(1)).putItem(Mockito.any(PutItemRequest.class));
        Assert.assertEquals(putItemRequest[0].getItem().get("version").getS(), padVersion(1));
    }

    @Test
    public void testPutSecretNewVersion() {
        String version = "foover";
        final PutItemRequest[] putItemRequest = new PutItemRequest[1];
        Mockito.when(dynamoDBClient.putItem(Mockito.any(PutItemRequest.class))).thenAnswer(invocationOnMock -> {
            Object[] args = invocationOnMock.getArguments();
            putItemRequest[0] = (PutItemRequest) args[0];
            return new PutItemResult();
        });

        JCredStash credStash = new JCredStash(dynamoDBClient, awskmsClient);
        credStash.putSecret("table", "mysecret", "foo", "alias/foo", new HashMap<>(), version);

        Mockito.verify(dynamoDBClient, VerificationModeFactory.times(1)).putItem(Mockito.any(PutItemRequest.class));
        Assert.assertEquals(putItemRequest[0].getItem().get("version").getS(), version);
    }

    @Test
    public void testPutSecretAutoIncrementVersion() {
        final PutItemRequest[] putItemRequest = new PutItemRequest[1];
        Mockito.when(dynamoDBClient.putItem(Mockito.any(PutItemRequest.class))).thenAnswer(invocationOnMock -> {
            Object[] args = invocationOnMock.getArguments();
            putItemRequest[0] = (PutItemRequest) args[0];
            return new PutItemResult();
        });

        JCredStash credStash = Mockito.spy(new JCredStash(dynamoDBClient, awskmsClient));
        Mockito.doReturn(padVersion(1)).when(credStash).getHighestVersion("table", "mysecret");
        credStash.putSecret("table", "mysecret", "foo", "alias/foo", new HashMap<>());

        Mockito.verify(dynamoDBClient, VerificationModeFactory.times(1)).putItem(Mockito.any(PutItemRequest.class));
        Assert.assertEquals(putItemRequest[0].getItem().get("version").getS(), padVersion(2));
    }

    private Map<String, AttributeValue> mockItem(String secretName, String newVersion, byte[] encryptedKeyBytes, byte[] contents, byte[] hmac) {

        Map<String, AttributeValue> item = new HashMap<>();
        item.put("name", new AttributeValue(secretName));
        item.put("version", new AttributeValue(newVersion));
        item.put("key", new AttributeValue(new String(Base64.getEncoder().encode(encryptedKeyBytes))));
        item.put("contents", new AttributeValue(new String(Base64.getEncoder().encode(contents))));
        item.put("hmac", new AttributeValue(new String(Hex.encodeHex(hmac))));
        return item;
    }

    @Test
    public void testGetSecret() {
        Mockito.when(dynamoDBClient.query(Mockito.any(QueryRequest.class))).thenAnswer(invocationOnMock -> {
            Object[] args = invocationOnMock.getArguments();
            final QueryRequest queryRequest = (QueryRequest) args[0];
            Assert.assertEquals("table", queryRequest.getTableName());
            return new QueryResult().withCount(1).withItems(Collections.singletonList(
                    mockItem("mysecret", padVersion(1), new byte[]{}, new byte[]{}, new byte[]{})
            ));
        });


        JCredStash credStash = Mockito.spy(new JCredStash(dynamoDBClient, awskmsClient));

        Mockito.doReturn("foo").when(credStash).getSecret(Mockito.any(JCredStash.StoredSecret.class), Mockito.anyMap());

        String secret = credStash.getSecret("table", "mysecret", new HashMap<>());

        Mockito.verify(dynamoDBClient, VerificationModeFactory.times(1)).query(Mockito.any(QueryRequest.class));
        Assert.assertEquals("foo", secret);
    }

    @Test
    public void testGetSecretWithVersion() {
        final GetItemRequest[] getItemRequest = new GetItemRequest[1];
        Mockito.when(dynamoDBClient.getItem(Mockito.any(GetItemRequest.class))).thenAnswer(invocationOnMock -> {
            Object[] args = invocationOnMock.getArguments();
            getItemRequest[0] = (GetItemRequest) args[0];
            return new GetItemResult();
        });

        JCredStash credStash = Mockito.spy(new JCredStash(dynamoDBClient, awskmsClient));
        Mockito.doReturn("foo").when(credStash).getSecret(Mockito.any(JCredStash.StoredSecret.class), Mockito.anyMap());

        credStash.getSecret("table", "mysecret", new HashMap<>(), padVersion(1));

        Mockito.verify(dynamoDBClient, VerificationModeFactory.times(1)).getItem(Mockito.any(GetItemRequest.class));
        Assert.assertEquals(getItemRequest[0].getKey().get("version").getS(), padVersion(1));
    }

    private String padVersion(int v) {
        return String.format("%019d", v);
    }
}
