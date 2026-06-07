package storage

import (
	"context"
	"fmt"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// User represents a user document in MongoDB.
type User struct {
	FirebaseUID string `bson:"firebaseUID"`
	Role        string `bson:"role"`
}

// MongoUserStore handles user data retrieval from MongoDB.
type MongoUserStore struct {
	client     *mongo.Client
	collection *mongo.Collection
}

// NewMongoUserStore initializes a new MongoUserStore.
func NewMongoUserStore(ctx context.Context, uri, dbName, collectionName string) (*MongoUserStore, error) {
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
	return &MongoUserStore{
		client:     client,
		collection: collection,
	}, nil
}

// GetUserByFirebaseUID retrieves a user by their Firebase UID.
func (m *MongoUserStore) GetUserByFirebaseUID(ctx context.Context, uid string) (*User, error) {
	var user User
	filter := bson.M{"firebaseId": uid}
	err := m.collection.FindOne(ctx, filter).Decode(&user)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, fmt.Errorf("no user found with Firebase UID %s", uid)
		}
		return nil, fmt.Errorf("error retrieving user: %w", err)
	}
	return &user, nil
}

// Close gracefully disconnects from MongoDB.
func (m *MongoUserStore) Close(ctx context.Context) error {
	return m.client.Disconnect(ctx)
}
