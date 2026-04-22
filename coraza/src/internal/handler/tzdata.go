package handler

// Embed the IANA timezone database so scheduled task validation/execution does
// not depend on host-level tzdata packages in binary deployments.
import _ "time/tzdata"
