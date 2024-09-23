package user

import (
	"context"
	"errors"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/expression"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

type DDBStore struct {
	client    *dynamodb.Client
	tableName string
}

func NewDDBStore(tableName string, client *dynamodb.Client) *DDBStore {
	return &DDBStore{
		tableName: tableName,
		client:    client,
	}
}

func (s *DDBStore) marshal(pk, id, firstName, lastName, email, passwordHash, createdAt string) (User, map[string]types.AttributeValue, error) {
	newUser := User{
		PK:           pk,
		ID:           id,
		FirstName:    firstName,
		LastName:     lastName,
		Email:        email,
		Vaults:       []string{},
		PasswordHash: passwordHash,
		CreatedAt:    createdAt,
	}
	item, err := attributevalue.MarshalMap(newUser)
	return newUser, item, err
}

func (s *DDBStore) Create(ctx context.Context, userFC User) (User, error) {
	emailExists, err := s.checkEmailExists(ctx, userFC.Email)
	if err != nil {
		return User{}, fmt.Errorf("failed to check if email exists: %w", err)
	}

	if emailExists {
		return User{}, &AlreadyExistsError{Email: userFC.Email}
	}

	newUser, item, err := s.marshal(
		userFC.PK,
		userFC.ID,
		userFC.FirstName,
		userFC.LastName,
		userFC.Email,
		userFC.PasswordHash,
		userFC.CreatedAt,
	)

	if err != nil {
		return User{}, fmt.Errorf("failed to marshal user: %w", err)
	}

	_, err = s.client.PutItem(ctx, &dynamodb.PutItemInput{
		TableName:           &s.tableName,
		Item:                item,
		ConditionExpression: aws.String("attribute_not_exists(SK)"),
	})

	if err != nil {
		var condErr *types.ConditionalCheckFailedException
		if errors.As(err, &condErr) {
			return User{}, &AlreadyExistsError{ID: newUser.ID}
		}
		return User{}, fmt.Errorf("failed to put item into DynamoDB: %w", err)
	}

	return newUser, nil
}

func (s *DDBStore) FindOneByEmail(ctx context.Context, email string) (User, error) {
	result, err := s.client.Query(ctx, &dynamodb.QueryInput{
		TableName:              &s.tableName,
		IndexName:              aws.String("email-index"),
		KeyConditionExpression: aws.String("email = :email"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":email": &types.AttributeValueMemberS{Value: email},
		},
		Limit: aws.Int32(1),
	})

	if err != nil {
		return User{}, fmt.Errorf("failed to query GSI for email: %w", err)
	}

	if len(result.Items) == 0 {
		return User{}, &NotFoundError{Email: email}
	}

	var user User
	err = attributevalue.UnmarshalMap(result.Items[0], &user)
	if err != nil {
		return User{}, fmt.Errorf("failed to unmarshal user data: %w", err)
	}

	return user, nil
}

func (s *DDBStore) FindOneByID(ctx context.Context, id string) (User, error) {
	response, err := s.client.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: &s.tableName,
		Key:       getKey(id),
	})

	if err != nil {
		return User{}, fmt.Errorf("GetItem DynamoDB operation failed for user ID='%s': %w", id, err)
	}

	if len(response.Item) == 0 {
		return User{}, &NotFoundError{ID: id}
	}

	var foundUser User
	err = attributevalue.UnmarshalMap(response.Item, &foundUser)
	if err != nil {
		return User{}, fmt.Errorf("failed to unmarshal expense: %w", err)
	}
	return foundUser, nil
}

func (s *DDBStore) checkEmailExists(ctx context.Context, email string) (bool, error) {
	result, err := s.client.Query(ctx, &dynamodb.QueryInput{
		TableName:              &s.tableName,
		IndexName:              aws.String("email-index"),
		KeyConditionExpression: aws.String("email = :email"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":email": &types.AttributeValueMemberS{Value: email},
		},
		Limit: aws.Int32(1),
	})

	if err != nil {
		return false, fmt.Errorf("failed to query GSI for email: %w", err)
	}

	return len(result.Items) > 0, nil
}

func (s *DDBStore) Delete(ctx context.Context, id string) error {
	if _, err := s.FindOneByID(ctx, id); err != nil {
		return &NotFoundError{ID: id}
	}

	_, err := s.client.DeleteItem(ctx, &dynamodb.DeleteItemInput{
		TableName: &s.tableName,
		Key:       getKey(id),
	})

	if err != nil {
		return fmt.Errorf("failed to delete user with ID=%q from table: %w", id, err)
	}

	return nil
}

func (s *DDBStore) FindAll(ctx context.Context) ([]User, error) {
	keyCond := expression.
		Key("PK").Equal(expression.Value(userPK))

	exprBuilder := expression.NewBuilder()
	exprBuilder.WithKeyCondition(keyCond)

	expr, err := expression.NewBuilder().
		WithKeyCondition(keyCond).
		Build()

	if err != nil {
		return nil, fmt.Errorf("failed to build expression for expense category query %w", err)
	}

	return s.query(ctx, expr)
}

func (s *DDBStore) query(ctx context.Context, expr expression.Expression) ([]User, error) {
	var users []User

	queryInput := dynamodb.QueryInput{
		TableName:                 &s.tableName,
		ExpressionAttributeNames:  expr.Names(),
		ExpressionAttributeValues: expr.Values(),
		KeyConditionExpression:    expr.KeyCondition(),
		FilterExpression:          expr.Filter(),
	}

	queryPaginator := dynamodb.NewQueryPaginator(s.client, &queryInput)

	for queryPaginator.HasMorePages() {
		response, err := queryPaginator.NextPage(ctx)

		if err != nil {
			return nil, fmt.Errorf("failed to query for expense categories: %w", err)
		}

		var resUsers []User
		err = attributevalue.UnmarshalListOfMaps(response.Items, &resUsers)
		if err != nil {
			return users, fmt.Errorf("failed to unmarshal query response for expense categories: %w", err)
		}

		users = append(users, resUsers...)
	}

	return users, nil
}

func getKey(sk string) map[string]types.AttributeValue {
	PK, err := attributevalue.Marshal(userPK)
	if err != nil {
		panic(err)
	}
	SK, err := attributevalue.Marshal(sk)
	if err != nil {
		panic(err)
	}
	return map[string]types.AttributeValue{"PK": PK, "SK": SK}
}