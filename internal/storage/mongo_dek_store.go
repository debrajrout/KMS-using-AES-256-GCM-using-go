package storage

import (
	"context"
	"fmt"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// DEKDocument represents a stored DEK document in MongoDB.
type DEKDocument struct {
	ID          primitive.ObjectID `bson:"_id,omitempty"`
	DEK         []byte             `bson:"dek"`
	MasterKeyID string             `bson:"masterKeyId"`
}

// MongoDEKStore handles DEK data in MongoDB.
type MongoDEKStore struct {
	client     *mongo.Client
	collection *mongo.Collection
}

// NewMongoDEKStore initializes a new MongoDEKStore.
func NewMongoDEKStore(ctx context.Context, uri, dbName, collectionName string) (*MongoDEKStore, error) {
	clientOpts := options.Client().ApplyURI(uri)
	client, err := mongo.Connect(ctx, clientOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to MongoDB: %w", err)
	}

	if err := client.Ping(ctx, nil); err != nil {
		_ = client.Disconnect(ctx)
		return nil, fmt.Errorf("failed to ping MongoDB: %w", err)
	}

	collection := client.Database(dbName).Collection(collectionName)
	return &MongoDEKStore{
		client:     client,
		collection: collection,
	}, nil
}

// InsertDEK inserts a new DEK document and returns its ID (hex string).
func (m *MongoDEKStore) InsertDEK(ctx context.Context, dekEncrypted []byte, masterKeyID string) (string, error) {
	res, err := m.collection.InsertOne(ctx, DEKDocument{
		DEK:         dekEncrypted,
		MasterKeyID: masterKeyID,
	})
	if err != nil {
		return "", fmt.Errorf("failed to insert DEK: %w", err)
	}
	oid, ok := res.InsertedID.(primitive.ObjectID)
	if !ok {
		return "", fmt.Errorf("failed to convert inserted ID to ObjectID")
	}
	return oid.Hex(), nil
}

// GetDEK retrieves a DEK document by ID.
func (m *MongoDEKStore) GetDEK(ctx context.Context, id string) (*DEKDocument, error) {
	oid, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		return nil, fmt.Errorf("invalid DEK ID format: %w", err)
	}

	var doc DEKDocument
	if err := m.collection.FindOne(ctx, bson.M{"_id": oid}).Decode(&doc); err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, fmt.Errorf("no DEK found with ID %s", id)
		}
		return nil, fmt.Errorf("error retrieving DEK: %w", err)
	}
	return &doc, nil
}

// DeleteDEK deletes a DEK document by its ID.
func (m *MongoDEKStore) DeleteDEK(ctx context.Context, id string) error {
	oid, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		return fmt.Errorf("invalid DEK ID format: %w", err)
	}

	_, err = m.collection.DeleteOne(ctx, bson.M{"_id": oid})
	if err != nil {
		return fmt.Errorf("failed to delete DEK: %w", err)
	}
	return nil
}

// Close disconnects from MongoDB.
func (m *MongoDEKStore) Close(ctx context.Context) error {
	return m.client.Disconnect(ctx)
}
