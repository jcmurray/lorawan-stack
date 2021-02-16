// Copyright © 2021 The Things Network Foundation, The Things Industries B.V.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package identityserver

import (
	"context"

	"github.com/jinzhu/gorm"
	"go.thethings.network/lorawan-stack/v3/pkg/errors"
	"go.thethings.network/lorawan-stack/v3/pkg/identityserver/store"
	"go.thethings.network/lorawan-stack/v3/pkg/ttnpb"
)

type entityRights struct {
	ids    ttnpb.Identifiers
	rights *ttnpb.Rights
}

func (is *IdentityServer) userApplicationRightsAfterTransfer(ctx context.Context, req *ttnpb.TransferUserRightsRequest) ([]entityRights, error) {
	var res []entityRights

	err := is.withDatabase(ctx, func(db *gorm.DB) error {
		membershipStore := store.GetMembershipStore(db)

		appIDs, err := membershipStore.FindMemberships(ctx, req.SenderIds.OrganizationOrUserIdentifiers(), "application", false)
		if err != nil {
			return err
		}
		for _, appID := range appIDs {
			senderRights, err := membershipStore.GetMember(
				ctx,
				req.SenderIds.GetOrganizationOrUserIdentifiers(),
				appID,
			)
			if err != nil {
				return err
			}
			if !senderRights.IncludesAll(ttnpb.RIGHT_APPLICATION_SETTINGS_COLLABORATORS) {
				continue
			}

			receiverRights, err := membershipStore.GetMember(
				ctx,
				req.ReceiverIds.GetOrganizationOrUserIdentifiers(),
				appID,
			)
			if err != nil && !errors.IsNotFound(err) {
				return err
			}
			if receiverRights.Implied().IncludesAll(senderRights.Implied().Rights...) {
				continue
			}

			res = append(res, entityRights{
				ids:    appID,
				rights: senderRights.Union(receiverRights).Unique(),
			})
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return res, nil
}

func (is *IdentityServer) userClientRightsAfterTransfer(ctx context.Context, req *ttnpb.TransferUserRightsRequest) ([]entityRights, error) {
	var res []entityRights

	err := is.withDatabase(ctx, func(db *gorm.DB) error {
		membershipStore := store.GetMembershipStore(db)

		cliIDs, err := membershipStore.FindMemberships(ctx, req.SenderIds.OrganizationOrUserIdentifiers(), "client", false)
		if err != nil {
			return err
		}
		for _, cliID := range cliIDs {
			senderRights, err := membershipStore.GetMember(
				ctx,
				req.SenderIds.GetOrganizationOrUserIdentifiers(),
				cliID,
			)
			if err != nil {
				return err
			}
			if !senderRights.IncludesAll(ttnpb.RIGHT_CLIENT_ALL) {
				continue
			}

			receiverRights, err := membershipStore.GetMember(
				ctx,
				req.ReceiverIds.GetOrganizationOrUserIdentifiers(),
				cliID,
			)
			if err != nil && !errors.IsNotFound(err) {
				return err
			}
			if receiverRights.Implied().IncludesAll(senderRights.Implied().Rights...) {
				continue
			}

			res = append(res, entityRights{
				ids:    cliID,
				rights: senderRights.Union(receiverRights).Unique(),
			})
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return res, nil
}

func (is *IdentityServer) userGatewayRightsAfterTransfer(ctx context.Context, req *ttnpb.TransferUserRightsRequest) ([]entityRights, error) {
	var res []entityRights

	err := is.withDatabase(ctx, func(db *gorm.DB) error {
		membershipStore := store.GetMembershipStore(db)

		gtwIDs, err := membershipStore.FindMemberships(ctx, req.SenderIds.OrganizationOrUserIdentifiers(), "gateway", false)
		if err != nil {
			return err
		}
		for _, gtwID := range gtwIDs {
			senderRights, err := membershipStore.GetMember(
				ctx,
				req.SenderIds.GetOrganizationOrUserIdentifiers(),
				gtwID,
			)
			if err != nil {
				return err
			}
			if !senderRights.IncludesAll(ttnpb.RIGHT_GATEWAY_SETTINGS_COLLABORATORS) {
				continue
			}

			receiverRights, err := membershipStore.GetMember(
				ctx,
				req.ReceiverIds.GetOrganizationOrUserIdentifiers(),
				gtwID,
			)
			if err != nil && !errors.IsNotFound(err) {
				return err
			}
			if receiverRights.Implied().IncludesAll(senderRights.Implied().Rights...) {
				continue
			}

			res = append(res, entityRights{
				ids:    gtwID,
				rights: senderRights.Union(receiverRights).Unique(),
			})
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return res, nil
}

func (is *IdentityServer) userOrganizationRightsAfterTransfer(ctx context.Context, req *ttnpb.TransferUserRightsRequest) ([]entityRights, error) {
	var res []entityRights

	err := is.withDatabase(ctx, func(db *gorm.DB) error {
		membershipStore := store.GetMembershipStore(db)

		orgIDs, err := membershipStore.FindMemberships(ctx, req.SenderIds.OrganizationOrUserIdentifiers(), "organization", false)
		if err != nil {
			return err
		}
		for _, orgID := range orgIDs {
			senderRights, err := membershipStore.GetMember(
				ctx,
				req.SenderIds.GetOrganizationOrUserIdentifiers(),
				orgID,
			)
			if err != nil {
				return err
			}
			if !senderRights.IncludesAll(ttnpb.RIGHT_ORGANIZATION_SETTINGS_MEMBERS) {
				continue
			}

			receiverRights, err := membershipStore.GetMember(
				ctx,
				req.ReceiverIds.GetOrganizationOrUserIdentifiers(),
				orgID,
			)
			if err != nil && !errors.IsNotFound(err) {
				return err
			}
			if receiverRights.Implied().IncludesAll(senderRights.Implied().Rights...) {
				continue
			}

			res = append(res, entityRights{
				ids:    orgID,
				rights: senderRights.Union(receiverRights).Unique(),
			})
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return res, nil
}
