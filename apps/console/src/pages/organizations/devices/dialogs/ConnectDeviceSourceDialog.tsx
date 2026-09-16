// Copyright (c) 2026 Probo Inc <hello@probo.com>.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

import {
  Button,
  Dialog,
  DialogContent,
  DialogFooter,
  Field,
  Textarea,
  useDialogRef,
  useToast,
} from "@probo/ui";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { useMutation } from "react-relay";
import { graphql } from "relay-runtime";

import type { ConnectDeviceSourceDialogMutation } from "#/__generated__/core/ConnectDeviceSourceDialogMutation.graphql";
import type { ConnectDeviceSourceDialogSyncMutation } from "#/__generated__/core/ConnectDeviceSourceDialogSyncMutation.graphql";

const createPrivateKeyJwtConnectorMutation = graphql`
  mutation ConnectDeviceSourceDialogMutation(
    $input: CreatePrivateKeyJwtConnectorInput!
  ) {
    createPrivateKeyJwtConnector(input: $input) {
      connector {
        id
        provider
      }
    }
  }
`;

const syncConnectorDevicesMutation = graphql`
  mutation ConnectDeviceSourceDialogSyncMutation(
    $input: SyncConnectorDevicesInput!
  ) {
    syncConnectorDevices(input: $input) {
      devicesSeen
      devicesRevoked
    }
  }
`;

interface ConnectDeviceSourceDialogProps {
  children: React.ReactNode;
  organizationId: string;
  /** The provider to connect, e.g. APPLE_BUSINESS_MANAGER. */
  provider: string;
  providerName: string;
  onConnected: () => void;
}

/**
 * Collects the three values an Apple Business Manager API account issues and
 * creates the connector, then runs the first sync immediately so the operator
 * sees their devices rather than an empty table until the hourly worker runs.
 *
 * The token endpoint, audience and scope are deliberately not form fields:
 * the server takes them from its own provider registration, so there is
 * nothing here for a customer to get wrong or for a phisher to redirect.
 */
export function ConnectDeviceSourceDialog({
  children,
  organizationId,
  provider,
  providerName,
  onConnected,
}: ConnectDeviceSourceDialogProps) {
  const { t } = useTranslation();
  const { toast } = useToast();
  const dialogRef = useDialogRef();

  const [clientId, setClientId] = useState("");
  const [keyId, setKeyId] = useState("");
  const [privateKeyPem, setPrivateKeyPem] = useState("");
  const [isConnecting, setIsConnecting] = useState(false);

  const [createConnector] = useMutation<ConnectDeviceSourceDialogMutation>(
    createPrivateKeyJwtConnectorMutation,
  );
  const [syncDevices] = useMutation<ConnectDeviceSourceDialogSyncMutation>(
    syncConnectorDevicesMutation,
  );

  const reset = () => {
    setClientId("");
    setKeyId("");
    setPrivateKeyPem("");
    setIsConnecting(false);
  };

  const connect = () => {
    if (!clientId.trim() || !keyId.trim() || !privateKeyPem.trim()) {
      return;
    }

    setIsConnecting(true);

    createConnector({
      variables: {
        input: {
          organizationId,
          provider,
          clientId: clientId.trim(),
          keyId: keyId.trim(),
          // The PEM is sent whitespace-intact: trimming the interior would
          // corrupt the base64 body, so only surrounding blank lines go.
          privateKeyPem: privateKeyPem.trim(),
        },
      },
      onCompleted: (response) => {
        const connector = response.createPrivateKeyJwtConnector?.connector;
        if (!connector) {
          setIsConnecting(false);
          toast({
            title: t("devices.deviceSources.messages.connectFailed"),
            variant: "error",
          });
          return;
        }

        syncDevices({
          variables: {
            input: { organizationId, connectorId: connector.id },
          },
          onCompleted: (syncResponse) => {
            reset();
            dialogRef.current?.close();
            onConnected();
            toast({
              title: t("devices.deviceSources.messages.connected", {
                provider: providerName,
              }),
              description: t("devices.deviceSources.messages.syncedCount", {
                count: syncResponse.syncConnectorDevices.devicesSeen,
              }),
              variant: "success",
            });
          },
          // The connector is created either way; only the first sync failed,
          // so the dialog closes and the periodic worker will retry. Saying so
          // is better than implying the connection itself did not take.
          onError: () => {
            reset();
            dialogRef.current?.close();
            onConnected();
            toast({
              title: t("devices.deviceSources.messages.connectedSyncPending", {
                provider: providerName,
              }),
              variant: "warning",
            });
          },
        });
      },
      onError: (error) => {
        setIsConnecting(false);
        toast({
          title: t("devices.deviceSources.messages.connectFailed"),
          description: error.message,
          variant: "error",
        });
      },
    });
  };

  return (
    <Dialog
      ref={dialogRef}
      trigger={children}
      onClose={reset}
      title={t("devices.deviceSources.title", { provider: providerName })}
    >
      <form
        onSubmit={(e) => {
          e.preventDefault();
          connect();
        }}
      >
        <DialogContent padded className="space-y-4">
          <p className="text-txt-secondary text-sm">
            {t("devices.deviceSources.description", { provider: providerName })}
          </p>
          <Field
            label={t("devices.deviceSources.fields.clientId")}
            value={clientId}
            onChange={(e: React.ChangeEvent<HTMLInputElement>) =>
              setClientId(e.target.value)}
            required
            autoFocus
          />
          <Field
            label={t("devices.deviceSources.fields.keyId")}
            value={keyId}
            onChange={(e: React.ChangeEvent<HTMLInputElement>) =>
              setKeyId(e.target.value)}
            required
          />
          <div className="space-y-1.5">
            <label className="text-sm font-medium">
              {t("devices.deviceSources.fields.privateKey")}
            </label>
            <Textarea
              value={privateKeyPem}
              onChange={(e: React.ChangeEvent<HTMLTextAreaElement>) =>
                setPrivateKeyPem(e.target.value)}
              placeholder="-----BEGIN PRIVATE KEY-----"
              rows={6}
              required
            />
            <p className="text-txt-tertiary text-xs">
              {t("devices.deviceSources.fields.privateKeyHelp")}
            </p>
          </div>
        </DialogContent>
        <DialogFooter>
          <Button
            type="submit"
            disabled={
              isConnecting
              || !clientId.trim()
              || !keyId.trim()
              || !privateKeyPem.trim()
            }
          >
            {isConnecting
              ? t("devices.deviceSources.actions.connecting")
              : t("devices.deviceSources.actions.connect")}
          </Button>
        </DialogFooter>
      </form>
    </Dialog>
  );
}
